package rs.ac.uns.ftn.informatika.jpa.service;

import com.google.common.hash.BloomFilter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.dao.DataIntegrityViolationException;
import com.google.common.hash.Funnels;
import java.nio.charset.StandardCharsets;

import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Isolation;
import rs.ac.uns.ftn.informatika.jpa.dto.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import rs.ac.uns.ftn.informatika.jpa.model.Role;
import rs.ac.uns.ftn.informatika.jpa.model.User;
import rs.ac.uns.ftn.informatika.jpa.model.Address;
import rs.ac.uns.ftn.informatika.jpa.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.informatika.jpa.service.UserService;

import java.time.*;
import java.time.temporal.ChronoUnit;
import org.springframework.transaction.annotation.Propagation;
import java.util.*;
import org.springframework.security.authentication.AuthenticationManager;
import rs.ac.uns.ftn.informatika.jpa.util.TokenUtils;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;


@Service
public class UserService implements UserDetailsService {

    private final Logger LOG = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private HttpServletRequest request; // Autowired HttpServletRequest


    @Autowired
    private RoleService roleService;

    @Autowired
    private MeterRegistry meterRegistry;

    private BloomFilter<String> usernameBloomFilter;

    private final Map<Integer, Deque<Instant>> followAttempts = new ConcurrentHashMap<>();
    private static final int MAX_FOLLOWS_PER_MINUTE = 1;    //50

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, TokenUtils tokenUtils, AuthenticationManager authenticationManager, MeterRegistry meterRegistry) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenUtils = tokenUtils;
        this.authenticationManager = authenticationManager;
        this.meterRegistry = meterRegistry;

        // Inicijalizacija Bloom filtera sa očekivanim brojem unosa i stopom greške
        this.usernameBloomFilter = BloomFilter.create(
                Funnels.stringFunnel(StandardCharsets.UTF_8),
                10000, // Očekivani broj korisničkih imena
                0.01   // Dozvoljena stopa greške (1%)
        );

        // Popunjavanje Bloom filtera postojećim korisničkim imenima
        loadExistingUsernames();

        //registrovanje custom metrike za broj aktivnih usera
        meterRegistry.gauge("active_users_last_24h", this,
                s -> s.countActiveUsersLast24h());

    }
    private void loadExistingUsernames() {
        List<String> usernames = userRepository.findAllUsernames();
        for (String username : usernames) {
            usernameBloomFilter.put(username);
        }
    }

    public int countActiveUsersLast24h() {
        LocalDateTime limit = LocalDateTime.now().minusHours(24);
        return (int) userRepository.countActiveUsersSince(limit);
    }

    @Autowired
    private EmailService emailService;

    @Transactional
    public synchronized ResponseEntity<?> register(UserDTO userDto) {
        if (!userDto.getPassword().equals(userDto.getConfirmPassword())) {
            return ResponseEntity.badRequest().body("Passwords do not match!");
        }
        if (userDto.getUsername() == null || userDto.getUsername().isEmpty()) {
            return ResponseEntity.badRequest().body("Username is required!");
        }
        if (userDto.getEmail() == null || userDto.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body("Email address is required!");
        }
        if (userDto.getPassword() == null || userDto.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("Password is required!");
        }
        if (userRepository.existsByUsername(userDto.getUsername())) {
            return ResponseEntity.badRequest().body("Username already exists!");
        }
        // Provera pomoću Bloom filtera
        if (usernameBloomFilter.mightContain(userDto.getUsername())) {
            // Dodatna provera u bazi (u slučaju false positive)
            if (userRepository.existsByUsername(userDto.getUsername())) {
                return ResponseEntity.badRequest().body("Username already exists!");
            }
        }
        if (userRepository.existsByEmail(userDto.getEmail())) {
            return ResponseEntity.badRequest().body("Email address already exists!");
        }

        // Simulacija kašnjenja (za testiranje konkurencije)
        try {
            Thread.sleep(5000); // Simulirajte kašnjenje
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // Ako korisničko ime ne postoji, dodajte ga u Bloom filter
        usernameBloomFilter.put(userDto.getUsername());

        User user = new User();
        user.setUsername(userDto.getUsername());
        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setName(userDto.getName());
        user.setSurname(userDto.getSurname());
        user.setActivated(false);
        user.setEnabled(true);
        user.setCreationTime(LocalDateTime.now());
        user.setLastActivityDate(LocalDateTime.now());

        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);

        Address address = new Address();
        address.setStreet(userDto.getStreet());
        address.setCity(userDto.getCity());
        address.setPostalCode(userDto.getPostalCode());
        address.setLatitude(userDto.getLatitude());
        address.setLongitude(userDto.getLongitude());
        user.setAddress(address);

        List<Role> roles = roleService.findByName("ROLE_USER");
        user.setRoles(roles);

        //userRepository.save(user);
        try {
            // Save user in the database
            userRepository.save(user);
        } catch (DataIntegrityViolationException ex) {
            // Handle constraint violations (for example, duplicate username or email)
            if (ex.getMessage().contains("uk_6dotkott2kjsp8vw4d0m25fb7")) {
                // Provide specific error message when username already exists
                return ResponseEntity.badRequest().body("Username already exists!");
            }
            // Return a general error message for other violations
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred during registration.");
        }


        emailService.sendActivationEmail(user.getEmail(), activationToken);

        return ResponseEntity.status(HttpStatus.CREATED).body(new UserDTO(user));
    }

public ResponseEntity<UserTokenState> login(
        @RequestBody JwtAuthenticationRequest authenticationRequest, HttpServletResponse response) {
    // Ukoliko kredencijali nisu ispravni, logovanje nece biti uspesno, desice se
    // AuthenticationException
    Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
            authenticationRequest.getUsername(), authenticationRequest.getPassword()));

    // Ukoliko je autentifikacija uspesna, ubaci korisnika u trenutni security
    // kontekst
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // Kreiraj token za tog korisnika
    User user = (User) authentication.getPrincipal();
    String jwt = tokenUtils.generateToken(user.getUsername());
    int expiresIn = tokenUtils.getExpiredIn();

    //Updejt lastActivity polja
    userRepository.findById(user.getId()).ifPresent(u -> {
        u.setLastActivityDate(LocalDateTime.now());
        userRepository.save(u);
    });

    // Vrati token kao odgovor na uspesnu autentifikaciju
    return ResponseEntity.ok(new UserTokenState(jwt, expiresIn, user.getId()));
}


    public ResponseEntity<?> activateUser(String token) {
        Optional<User> userOptional = userRepository.findByActivationToken(token);
        if (!userOptional.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Nevažeći aktivacioni token.");
        }

        User user = userOptional.get();
        user.setActivated(true);
        user.setActivationToken(null);
        user.setLastActivityDate(LocalDateTime.now());

        userRepository.save(user);

        return ResponseEntity.ok("Korisnik je uspešno aktiviran.");
    }

    public boolean changePassword(Integer userId, ChangePasswordDTO changePasswordDTO) {
        User user = userRepository.findById(userId).orElseThrow(() -> new NoSuchElementException("User not found"));

        if (!passwordEncoder.matches(changePasswordDTO.getOldPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Old password is incorrect");
        }

        if (!changePasswordDTO.getNewPassword().equals(changePasswordDTO.getConfirmPassword())) {
            throw new IllegalArgumentException("New passwords do not match");
        }

        user.setPassword(passwordEncoder.encode(changePasswordDTO.getNewPassword()));
        userRepository.save(user);

        return true;
    }

    public boolean changeLastActivty(Integer userId, LocalDateTime lastActivty) {
        User user = userRepository.findById(userId).orElseThrow(() -> new NoSuchElementException("User not found"));



        if (lastActivty == null || lastActivty.isBefore(user.getLastActivityDate())) {
            throw new IllegalArgumentException("Last activity is incorrect");
        }

        user.setLastActivityDate(lastActivty);
        userRepository.save(user);

        return true;
    }

    public UserDTO getUserProfile(Integer userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NoSuchElementException("User not found"));

        return new UserDTO(user);
    }

    public User updateUserProfile(Integer userId, UserDTO userProfileUpdateDto) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NoSuchElementException("User not found"));

        user.setName(userProfileUpdateDto.getName());
        user.setSurname(userProfileUpdateDto.getSurname());

        Address address = user.getAddress();
        if (address == null) {
            address = new Address();
        }

        address.setStreet(userProfileUpdateDto.getStreet());
        address.setCity(userProfileUpdateDto.getCity());
        address.setPostalCode(userProfileUpdateDto.getPostalCode());
        address.setLatitude(userProfileUpdateDto.getLatitude());
        address.setLongitude(userProfileUpdateDto.getLongitude());

        user.setAddress(address);

        return userRepository.save(user);
    }

    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        } else {
            return user;
        }
    }

    public List<UserInfoDTO> getAllUsersInfo() {
        List<User> users = userRepository.findAll();
        List<UserInfoDTO> userDTOs = new ArrayList<>();

        for (User user : users) {
            Integer numberOfPosts = user.getPosts().size();
            Integer numberOfFollowing = user.getFollowing().size();
            UserInfoDTO userDTO = new UserInfoDTO(user.getId(), user.getUsername(), user.getName(), user.getSurname(), user.getEmail(), numberOfPosts, numberOfFollowing);
            userDTOs.add(userDTO);
        }

        return userDTOs;
    }


   
    @Scheduled(cron = "0 0 18 * * ?")
    public void sendInactivityReports() {
        LocalDateTime now = LocalDateTime.now();
        System.out.println("Funkcija se izvrsava");

        List<User> allUsers = userRepository.findAll();
        System.out.println("Do kraja se izvrsava");
        for (User user : allUsers) {
            LocalDateTime lastActivity = user.getLastActivityDate();
            long daysBetween = ChronoUnit.DAYS.between(lastActivity, now);
            System.out.println("vrednost iz baze: ");
            System.out.println(lastActivity);
            System.out.println(daysBetween);

            // Proveri da li je korisnik neaktivan najmanje 7 dana
            // i da li je daysBetween deljiv sa 7 (7, 14, 21...)
            if (daysBetween >= 7 && daysBetween % 7 == 0) {
                System.out.println("Uslov zadovoljen.");
                emailService.sendUnactiveReportEmail(user, lastActivity);

            }
        }
    }

    public Integer getRole(Integer userId){
        return userRepository.findRoleIdByUserId(userId);
    }


    public String getClientIP() {
        String remoteAddr = "";
        if (request != null) {
            remoteAddr = request.getHeader("X-FORWARDED-FOR");
            if (remoteAddr == null || remoteAddr.isEmpty()) {
                remoteAddr = request.getRemoteAddr();
            }
        }
        return remoteAddr;
    }


    public boolean isFollowing(Integer currentUserId, Integer targetUserId) {
        return userRepository.isFollowing(currentUserId, targetUserId);
    }

    private boolean canFollow(Integer followerId) {
        Instant now = Instant.now();    //tacan trenutak kada je korisnik kliknuo follow
        //followAttempts je mapa svih korisnika (kljuc) a vrednost joj je lista svih vremena kad su pokusali da zaprate
        //timestamps je lista bas za tog jednog korisnika
        Deque<Instant> timestamps = followAttempts.computeIfAbsent(followerId, k -> new ConcurrentLinkedDeque<>());

        // Izbaci sve starije od 1 minuta
        while (!timestamps.isEmpty() &&
                Duration.between(timestamps.peekFirst(), now).toMinutes() >= 1) {   //peekFirst=najstariji
            timestamps.pollFirst(); //brise se zapis stariji od 1min
        }

        if (timestamps.size() >= MAX_FOLLOWS_PER_MINUTE) {
            return false; // limit probijen
        }

        timestamps.addLast(now);    //dodaje trenutni pokusaj na kraj liste
        return true;
    }


    @Transactional(isolation = Isolation.REPEATABLE_READ, propagation = Propagation.REQUIRED)
    //@RateLimiter(name = "follow-limit", fallbackMethod = "standardFallback")
    public ResponseEntity<Map<String, String>> followUser(Integer followerId, Integer followingId) {
        if (!canFollow(followerId)) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "You can follow maximum " + MAX_FOLLOWS_PER_MINUTE + " users per minute");
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
        }

        if (followerId.equals(followingId)) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "You cannot follow yourself");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }

        User toFollow = userRepository.findByIdWithLock(followingId)
                .orElseThrow(() -> new NoSuchElementException("User to follow not found"));

        if (userRepository.isFollowing(followerId, followingId)) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Already following this user");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }

        //usporavanje izvrsenja
//        try {
//            Thread.sleep(4000);
//        } catch (InterruptedException e) {
//            Thread.currentThread().interrupt();
//            throw new RuntimeException("Thread interrupted during follow operation");
//        }

        User follower = userRepository.findById(followerId)
                .orElseThrow(() -> new NoSuchElementException("Follower not found"));

        follower.getFollowing().add(toFollow);
        userRepository.save(follower);

        Map<String, String> successResponse = new HashMap<>();
        successResponse.put("message", "You are now following " + toFollow.getUsername());
        return ResponseEntity.ok(successResponse);
    }

    @Transactional
    public void simulateFollowWithDelay(Integer followerId, Integer followingId) {
            LOG.info("### START follow simulation for user {} at {}", followerId, LocalTime.now());
            followUser(followerId, followingId);
            LOG.info("### END follow simulation for user {} at {}", followerId, LocalTime.now());
    }


    @Transactional
    public ResponseEntity<Map<String, String>> unfollowUser(Integer followerId, Integer followingId) {
        User follower = userRepository.findById(followerId)
                .orElseThrow(() -> new NoSuchElementException("Follower not found"));
        User toUnfollow = userRepository.findById(followingId)
                .orElseThrow(() -> new NoSuchElementException("User to unfollow not found"));

        if (!follower.getFollowing().contains(toUnfollow)) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "You are not following this user");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }

        follower.getFollowing().remove(toUnfollow);
        userRepository.save(follower);

        Map<String, String> successResponse = new HashMap<>();
        successResponse.put("message", "You have unfollowed " + toUnfollow.getUsername());
        return ResponseEntity.ok(successResponse);
    }

    public List<UserInfoDTO> getFollowing(Integer userId) {
        List<User> following = userRepository.findFollowingByUserId(userId);
        List<UserInfoDTO> userInfoDTOs = new ArrayList<>();

        for (User user : following) {
            userInfoDTOs.add(new UserInfoDTO(
                    user.getId(),
                    user.getUsername(),
                    user.getName(),
                    user.getSurname(),
                    user.getEmail(),
                    user.getPosts().size(),
                    user.getFollowing().size()
            ));
        }

        return userInfoDTOs;
    }

    public List<UserInfoDTO> getFollowers(Integer userId) {
        List<User> followers = userRepository.findFollowersByUserId(userId);
        List<UserInfoDTO> userInfoDTOs = new ArrayList<>();

        for (User user : followers) {
            userInfoDTOs.add(new UserInfoDTO(
                    user.getId(),
                    user.getUsername(),
                    user.getName(),
                    user.getSurname(),
                    user.getEmail(),
                    user.getPosts().size(),
                    user.getFollowing().size()
            ));
        }

        return userInfoDTOs;
    }

    @Transactional
    public void deleteInactiveAccounts() {
        System.out.println("Method deleteInactiveAccounts started");
        List<User> inactiveUsers = userRepository.findInactiveUsers();

        System.out.println("Number of inactive users found: " + inactiveUsers.size());

        for (User user : inactiveUsers) {
            System.out.println("Deleting user: " + user.getUsername());
            userRepository.delete(user);
        }
        System.out.println("Method deleteInactiveAccounts completed");
    }

    @Transactional
    @Scheduled(cron = "0 0 0 L * ?")
    public void cleanUpInactiveAccounts() {
        System.out.println("Scheduled task triggered");
        LOG.info("Scheduled task triggered");
        deleteInactiveAccounts();
        System.out.println("Scheduled cleanup of inactive accounts completed.");
    }

    public Page<UserInfoDTO> getAllUsersPaged(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        return userRepository.findAll(pageable).map(UserInfoDTO::new);
    }

    public Page<UserInfoDTO> searchUsers(String name, String surname, String email, int minPosts, int maxPosts, String sortField, String sortDirection, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);

        Page<User> users = userRepository.searchUsers(
                name,
                surname,
                email,
                minPosts,
                maxPosts,
                sortField,
                sortDirection,
                pageable
        );

        return users.map(user -> new UserInfoDTO(
                user.getId(),
                user.getUsername(),
                user.getName(),
                user.getSurname(),
                user.getEmail(),
                user.getPosts().size(),
                user.getFollowing().size()
        ));
    }

    public List<SimpleUserDTO> getAllSimpleUsers() {
        List<User> users = userRepository.findAll();
        List<SimpleUserDTO> dtoList = new ArrayList<>();
        for (User user : users) {
            dtoList.add(new SimpleUserDTO(user.getId(), user.getUsername()));
        }
        return dtoList;
    }



}
