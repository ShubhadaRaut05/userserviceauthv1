package com.shubhada.userservice.services;

import com.shubhada.userservice.dtos.UserDto;
import com.shubhada.userservice.exceptions.UserAlreadyExistsException;
import com.shubhada.userservice.exceptions.UserDoesNotExistException;
import com.shubhada.userservice.models.Session;
import com.shubhada.userservice.models.SessionStatus;
import com.shubhada.userservice.models.User;
import com.shubhada.userservice.repositories.SessionRepository;
import com.shubhada.userservice.repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.util.MultiValueMapAdapter;

import java.util.Date;
import java.util.HashMap;
import java.util.Optional;

@Service
public class AuthService {

    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private UserRepository userRepository;
    private SessionRepository sessionRepository;
    public AuthService(UserRepository userRepository,SessionRepository sessionRepository){
        this.userRepository=userRepository;
        this.sessionRepository=sessionRepository;
        this.bCryptPasswordEncoder=new BCryptPasswordEncoder();
    }
    public UserDto signUp(String email,String password) throws UserAlreadyExistsException {
        Optional<User> userOptional=userRepository.findByEmail(email);
        if(!userOptional.isEmpty()){

            throw new UserAlreadyExistsException("User with"+ email+ " already exists");
        }
        User user=new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        User savedUser=userRepository.save(user);
        return UserDto.from(savedUser);
    }
    public ResponseEntity<UserDto> login(String email,String password ) throws UserDoesNotExistException {

        Optional<User>  userOptional=userRepository.findByEmail(email);
        if(userOptional.isEmpty()){

            throw new UserDoesNotExistException("User with email"+email+"doesn't exist");
        }
        User user=userOptional.get();
        if(!bCryptPasswordEncoder.matches(password,user.getPassword())){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        //password has matched
        String token= RandomStringUtils.randomAscii(20);
        UserDto userDto=UserDto.from(user);

        //sent authentication token as the part of header
        MultiValueMapAdapter<String,String> headers=new MultiValueMapAdapter<>(new HashMap<>());
        headers.add("AUTH_TOKEN",token);
        Session session=new Session();
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(token);
        session.setUser(user);
        sessionRepository.save(session);
        ResponseEntity<UserDto> response=new ResponseEntity<>(
                userDto,
                headers,
                HttpStatus.OK
        );
        return response;
    }

    public SessionStatus validate(String token,Long userId){
        Optional<Session> sessionOptional=sessionRepository.findByTokenAndUser_Id(token,userId);
        if(sessionOptional.isEmpty()){
            return SessionStatus.INVALID;
        }
        Session session=sessionOptional.get();
        if(!session.getSessionStatus().equals(SessionStatus.ACTIVE))
        {
            return SessionStatus.EXPIRED;
        }

       /* if(!session.getExpiringAt()>new Date()){
            return SessionStatus.EXPIRED;
        }*/

        return SessionStatus.ACTIVE;

    }
    public ResponseEntity<Void> logout(String token,Long userId){
        Optional<Session> sessionOptional=sessionRepository.findByTokenAndUser_Id(token,userId);
        if(sessionOptional.isEmpty()){
            return null;
        }
        Session session=sessionOptional.get();
        session.setSessionStatus(SessionStatus.LOGGED_OUT);
        sessionRepository.save(session);
        return ResponseEntity.ok().build();

    }

}
