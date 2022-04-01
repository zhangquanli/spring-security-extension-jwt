package com.github.zhangquanli.security.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Base configurer for an OAuth 2.0 component (e.g. protocol endpoint).
 *
 * @author Joe Grandja
 */
abstract class AbstractOAuth2Configurer {
    abstract <B extends HttpSecurityBuilder<B>> void init(B builder);

    abstract <B extends HttpSecurityBuilder<B>> void configure(B builder);

    abstract RequestMatcher getRequestMatcher();
}
