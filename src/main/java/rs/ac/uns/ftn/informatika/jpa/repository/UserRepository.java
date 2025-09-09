package rs.ac.uns.ftn.informatika.jpa.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import rs.ac.uns.ftn.informatika.jpa.model.User;

import java.time.LocalDate;

import javax.persistence.LockModeType;
import javax.persistence.QueryHint;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

//    @Query("select u from User u where u.username = ?1")


    User findByUsername(String username);

    @Query("select u from User u where u.email = ?1")
    Optional<User> findByEmail(String email);

    @Query("select u from User u where u.id = ?1")
    Optional<User> findById(Integer id);

    @Query("select count(u) > 0 from User u where u.username = ?1")
    boolean existsByUsername(String username);

    @Query("select count(u) > 0 from User u where u.email = ?1")
    boolean existsByEmail(String email);

    Optional<User> findByActivationToken(String activationToken);

    @Query(value = "SELECT ur.role_id FROM user_role ur WHERE ur.user_id = :userId", nativeQuery = true)
    Integer findRoleIdByUserId(@Param("userId") Integer userId);


    @Query("SELECT CASE WHEN COUNT(uf) > 0 THEN TRUE ELSE FALSE END " +
            "FROM User u JOIN u.following uf WHERE u.id = :followerId AND uf.id = :followingId")
    boolean isFollowing(@Param("followerId") Integer followerId, @Param("followingId") Integer followingId);

    @Query("SELECT u.following FROM User u WHERE u.id = :userId")
    List<User> findFollowingByUserId(@Param("userId") Integer userId);

    @Query("SELECT u FROM User u JOIN u.following f WHERE f.id = :userId")
    List<User> findFollowersByUserId(@Param("userId") Integer userId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT u FROM User u WHERE u.id = :id")
    @QueryHints({@QueryHint(name = "javax.persistence.lock.timeout", value ="5000")})
    Optional<User> findByIdWithLock(@Param("id") Integer id);

    @Query("SELECT u FROM User u WHERE u.activated = false")
    List<User> findInactiveUsers();

    Page<User> findAll(Pageable pageable);

    @Query("SELECT u FROM User u " +
            "WHERE (:name IS NULL OR LOWER(u.name) LIKE LOWER(CONCAT('%', :name, '%'))) AND " +
            "(:surname IS NULL OR LOWER(u.surname) LIKE LOWER(CONCAT('%', :surname, '%'))) AND " +
            "(:email IS NULL OR LOWER(u.email) LIKE LOWER(CONCAT('%', :email, '%'))) AND " +
            "(:minPosts = 0 OR SIZE(u.posts) >= :minPosts) AND " +
            "(:maxPosts = 2147483647 OR SIZE(u.posts) <= :maxPosts) " +
            "ORDER BY " +
            "CASE WHEN :sortField = 'following' AND :sortDirection = 'asc' THEN SIZE(u.following) END ASC, " +
            "CASE WHEN :sortField = 'following' AND :sortDirection = 'desc' THEN SIZE(u.following) END DESC, " +
            "CASE WHEN :sortField = 'email' AND :sortDirection = 'asc' THEN u.email END ASC, " +
            "CASE WHEN :sortField = 'email' AND :sortDirection = 'desc' THEN u.email END DESC")
    Page<User> searchUsers(
            @Param("name") String name,
            @Param("surname") String surname,
            @Param("email") String email,
            @Param("minPosts") Integer minPosts,
            @Param("maxPosts") Integer maxPosts,
            @Param("sortField") String sortField,
            @Param("sortDirection") String sortDirection,
            Pageable pageable);




    @Query("SELECT u.username FROM User u")
    List<String> findAllUsernames();

    @Query("SELECT COUNT(DISTINCT p.creator.id) FROM Post p")
    long countUsersWithPosts();

    @Query("SELECT COUNT(u) FROM User u WHERE u.id NOT IN (SELECT DISTINCT p.creator.id FROM Post p) AND u.id IN (SELECT DISTINCT c.user.id FROM Comment c)")
    long countUsersWithOnlyComments();

    @Query("SELECT COUNT(u) FROM User u")
    long countAllUsers();

    Optional<User> findOptionalByUsername(String username);

    @Query("SELECT COUNT(u) FROM User u WHERE u.lastActivityDate >= :since")
    long countActiveUsersSince(@Param("since") LocalDateTime since);

}

