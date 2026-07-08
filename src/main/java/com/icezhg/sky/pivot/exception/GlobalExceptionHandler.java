package com.icezhg.sky.pivot.exception;

import com.icezhg.sky.pivot.common.Constants;
import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.security.JwtService;
import com.icezhg.sky.pivot.service.AuthService;
import com.icezhg.sky.pivot.service.CryptoService;
import com.icezhg.sky.pivot.service.MasterPasswordService;
import com.icezhg.sky.pivot.service.WeChatService;
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
        return ResponseEntity.badRequest().body(ApiResponse.error(HttpStatus.BAD_REQUEST.value(), message));
    }

    @ExceptionHandler(JwtService.TokenValidationException.class)
    public ResponseEntity<ApiResponse<Void>> handleTokenValidation(JwtService.TokenValidationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiResponse.error(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token"));
    }

    @ExceptionHandler(MasterPasswordService.WrongMasterPasswordException.class)
    public ResponseEntity<ApiResponse<Void>> handleWrongPassword(MasterPasswordService.WrongMasterPasswordException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse.error(HttpStatus.FORBIDDEN.value(), "Wrong master password"));
    }

    @ExceptionHandler(MasterPasswordService.MasterPasswordAlreadySetException.class)
    public ResponseEntity<ApiResponse<Void>> handleAlreadySet(MasterPasswordService.MasterPasswordAlreadySetException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error(HttpStatus.BAD_REQUEST.value(), "Master password already set"));
    }

    @ExceptionHandler(MasterPasswordService.MasterPasswordNotSetException.class)
    public ResponseEntity<ApiResponse<Void>> handleNotSet(MasterPasswordService.MasterPasswordNotSetException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error(HttpStatus.BAD_REQUEST.value(), "Master password not set"));
    }

    @ExceptionHandler(MasterPasswordService.SamePasswordException.class)
    public ResponseEntity<ApiResponse<Void>> handleSamePassword(MasterPasswordService.SamePasswordException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error(HttpStatus.BAD_REQUEST.value(), "New password must differ from current"));
    }

    @ExceptionHandler(MasterPasswordService.UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(MasterPasswordService.UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ApiResponse.error(HttpStatus.NOT_FOUND.value(), ex.getMessage()));
    }

    @ExceptionHandler(AuthService.AccountDeletedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountDeleted(AuthService.AccountDeletedException ex) {
        return ResponseEntity.status(Constants.HTTP_STATUS_451)
            .body(ApiResponse.error(Constants.HTTP_STATUS_451, "Account has been deleted"));
    }

    @ExceptionHandler(AuthService.AccountDisabledException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountDisabled(AuthService.AccountDisabledException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse.error(HttpStatus.FORBIDDEN.value(), "Account has been disabled"));
    }

    @ExceptionHandler(WeChatService.WeChatException.class)
    public ResponseEntity<ApiResponse<Void>> handleWeChat(WeChatService.WeChatException ex) {
        log.error("WeChat API error", ex);
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(ApiResponse.error(HttpStatus.BAD_GATEWAY.value(), "WeChat service error: " + ex.getMessage()));
    }

    @ExceptionHandler(CryptoService.CryptoException.class)
    public ResponseEntity<ApiResponse<Void>> handleCrypto(CryptoService.CryptoException ex) {
        log.error("Crypto operation failed", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal encryption error"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest()
            .body(ApiResponse.error(HttpStatus.BAD_REQUEST.value(), ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneral(Exception ex) {
        log.error("Unexpected error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal server error"));
    }
}
