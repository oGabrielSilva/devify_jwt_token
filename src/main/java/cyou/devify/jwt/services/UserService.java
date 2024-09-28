package cyou.devify.jwt.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import cyou.devify.jwt.entities.User;
import cyou.devify.jwt.exceptions.Forbidden;
import cyou.devify.jwt.repositories.UserRepository;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    UserRepository repository;

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByEmail(username);
    }

    public User getCurrentAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getPrincipal() instanceof User ? (User) authentication.getPrincipal() : null;
    }

    public User getCurrentAuthenticatedUserOrThrowsForbidden() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication.getPrincipal() instanceof User))
            throw new Forbidden();
        return (User) authentication.getPrincipal();
    }

    public boolean isAuthenticated() {
        return getCurrentAuthenticatedUser() != null;
    }
}
