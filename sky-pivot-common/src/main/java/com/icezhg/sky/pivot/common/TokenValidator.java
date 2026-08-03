package com.icezhg.sky.pivot.common;

import java.util.Optional;

public interface TokenValidator {

    Optional<Long> tryValidate(String token);
}
