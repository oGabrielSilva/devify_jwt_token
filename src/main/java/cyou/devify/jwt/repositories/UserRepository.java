package cyou.devify.jwt.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import cyou.devify.jwt.entities.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByEmail(String email);
}
