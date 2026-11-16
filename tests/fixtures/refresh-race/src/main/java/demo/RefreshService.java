package demo;

import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class RefreshService {
    private final RefreshTokenRepository repo;

    public RefreshService(RefreshTokenRepository repo) {
        this.repo = repo;
    }

    public String refresh(String token) {
        RefreshToken stored = repo.findByToken(token).orElseThrow();
        if (stored.isRevoked()) {
            throw new IllegalStateException("revoked");
        }
        stored.setRevoked(true);
        repo.save(stored);
        RefreshToken next = new RefreshToken(UUID.randomUUID().toString());
        repo.save(next);
        return next.getToken();
    }
}
