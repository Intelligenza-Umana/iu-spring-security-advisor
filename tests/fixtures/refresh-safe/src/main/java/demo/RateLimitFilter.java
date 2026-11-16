package demo;

import io.github.bucket4j.Bucket;
import org.springframework.web.filter.OncePerRequestFilter;

public abstract class RateLimitFilter extends OncePerRequestFilter {
    protected Bucket bucket;
}
