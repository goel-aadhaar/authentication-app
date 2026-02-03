package com.aadhaar.auth.auth_backend.repositories;

import com.aadhaar.auth.auth_backend.enitites.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken , UUID> {

}
