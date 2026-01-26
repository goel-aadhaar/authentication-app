package com.aadhaar.auth.auth_backend.controllers;

import com.aadhaar.auth.auth_backend.dtos.UserDto;
import com.aadhaar.auth.auth_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/users")
@AllArgsConstructor
public class UserController {

    private final UserService userService;

//    create user
    @PostMapping
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(userService.createUser(userDto));
    }
//    get all users
    @GetMapping
    public ResponseEntity<Iterable<UserDto>> getAllUsers() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(userService.getAllUsers());
    }
//    get user by email
    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String email) {

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(userService.getUserByEmail(email));

    }

//    delete user
    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUserById(@PathVariable String userId) {

        userService.deleteUser(userId);

        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUserById(@RequestBody UserDto userDto, @PathVariable String userId) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(userService.updateUser(userDto , userId));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable String userId) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(userService.getUserById(userId));
    }

}
