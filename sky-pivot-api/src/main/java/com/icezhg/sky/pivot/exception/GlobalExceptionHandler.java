package com.icezhg.sky.pivot.exception;

import com.icezhg.sky.pivot.common.Constants;
import com.icezhg.sky.pivot.dto.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
            .map(e -> e.getField() + ": " + e.getDefaultMessage())
            .reduce((a, b) -> a + "; " + b)
            .orElse("Validation failed");
        return ResponseEntity.badRequest().body(ApiResponse.error("400", message));
    }

    @ExceptionHandler(TokenValidationException.class)
    public ResponseEntity<ApiResponse<Void>> handleTokenValidation(TokenValidationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiResponse.error("401", "Invalid or expired token"));
    }

    @ExceptionHandler(WrongMasterPasswordException.class)
    public ResponseEntity<ApiResponse<Void>> handleWrongPassword(WrongMasterPasswordException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse.error("403", "Wrong master password"));
    }

    @ExceptionHandler(MasterPasswordAlreadySetException.class)
    public ResponseEntity<ApiResponse<Void>> handleAlreadySet(MasterPasswordAlreadySetException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error("400", "Master password already set"));
    }

    @ExceptionHandler(MasterPasswordNotSetException.class)
    public ResponseEntity<ApiResponse<Void>> handleNotSet(MasterPasswordNotSetException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error("400", "Master password not set"));
    }

    @ExceptionHandler(SamePasswordException.class)
    public ResponseEntity<ApiResponse<Void>> handleSamePassword(SamePasswordException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error("400", "New password must differ from current"));
    }

    @ExceptionHandler(MasterPasswordUserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(MasterPasswordUserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ApiResponse.error("404", ex.getMessage()));
    }

    @ExceptionHandler(AccountDeletedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountDeleted(AccountDeletedException ex) {
        return ResponseEntity.status(Constants.HTTP_STATUS_451)
            .body(ApiResponse.error(String.valueOf(Constants.HTTP_STATUS_451), "Account has been deleted"));
    }

    @ExceptionHandler(AccountDisabledException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountDisabled(AccountDisabledException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse.error("403", "Account has been disabled"));
    }

    @ExceptionHandler(WeChatApiException.class)
    public ResponseEntity<ApiResponse<Void>> handleWeChat(WeChatApiException ex) {
        log.error("WeChat API error", ex);
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(ApiResponse.error("502", "WeChat service error: " + ex.getMessage()));
    }

    @ExceptionHandler(CryptoException.class)
    public ResponseEntity<ApiResponse<Void>> handleCrypto(CryptoException ex) {
        log.error("Crypto operation failed", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse.error("500", "Internal encryption error"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error("400", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneral(Exception ex) {
        log.error("Unexpected error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse.error("500", "Internal server error"));
    }
}
