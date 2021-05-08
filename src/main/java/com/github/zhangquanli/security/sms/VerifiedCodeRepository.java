package com.github.zhangquanli.security.sms;

public interface VerifiedCodeRepository {
    String load(String mobile);

    void save(String mobile, String verifiedCode);

    void remove(String mobile);

    boolean contains(String mobile);
}
