package cyou.devify.jwt.entities;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import cyou.devify.jwt.enums.Role;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity(name = "user_entity")
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(updatable = false, name = "user_public_uuid")
    private UUID uuid = UUID.randomUUID();

    @Column(length = 50, nullable = false)
    private String name = "";

    @Column(unique = true, length = 150, nullable = false)
    private String email;

    private Role authority = Role.COMMON;

    @Column(nullable = false)
    private String password;

    @CreationTimestamp
    @Column(updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    private Instant updatedAt;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        var roles = new ArrayList<GrantedAuthority>();
        switch (authority) {
            case ROOT:
                roles.addAll(List.of(new SimpleGrantedAuthority("ROLE_" + Role.ROOT.asString()),
                        new SimpleGrantedAuthority("ROLE_" + Role.ADMIN.asString()),
                        new SimpleGrantedAuthority("ROLE_" + Role.MODERATOR.asString()),
                        new SimpleGrantedAuthority("ROLE_" + Role.HELPER.asString()),
                        new SimpleGrantedAuthority("ROLE_" + Role.EDITOR.asString())));
                break;
            case ADMIN:
                roles.addAll(List.of(new SimpleGrantedAuthority("ROLE_" + Role.ADMIN.asString()),
                        new SimpleGrantedAuthority("ROLE_" + Role.MODERATOR.asString()),
                        new SimpleGrantedAuthority("ROLE_" + Role.HELPER.asString()),
                        new SimpleGrantedAuthority("ROLE_" + Role.EDITOR.asString())));
                break;
            case MODERATOR:
                roles.add(new SimpleGrantedAuthority("ROLE_" + Role.MODERATOR.asString()));
                roles.add(new SimpleGrantedAuthority("ROLE_" + Role.HELPER.asString()));
                roles.add(new SimpleGrantedAuthority("ROLE_" + Role.EDITOR.asString()));
                break;
            case HELPER:
                roles.add(new SimpleGrantedAuthority("ROLE_" + Role.HELPER.asString()));
                roles.add(new SimpleGrantedAuthority("ROLE_" + Role.EDITOR.asString()));
                break;
            case COMMON:
                break;
            default:
                roles.add(new SimpleGrantedAuthority("ROLE_" + Role.EDITOR.asString()));
                break;
        }
        roles.add(new SimpleGrantedAuthority("ROLE_" + Role.COMMON.asString()));
        return roles;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }
}
