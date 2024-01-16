package com.springboot.jwt.security.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.jwt.UnauthorizedException;
import com.springboot.jwt.domain.UserDTO;
import com.springboot.jwt.model.User;
import com.springboot.jwt.security.JwtTokenUtil;
import com.springboot.jwt.security.JwtUser;

@RestController
public class AuthenticationContoller {

	@Value("${jwt.header}")
	private String tokenHeader; //HeaderName="Authorization"

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;  //Wraper to JWTToken

	@PostMapping(value="/login")
	public ResponseEntity<UserDTO> login(@RequestBody User user, HttpServletRequest request, HttpServletResponse response){

		try {
			
			//VErifying the Username and password and generating the authentication object with the username and password

			Authentication authentication=authenticationManager.
					authenticate(new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));

			//authentication.getPrincipal(); ==> UserName ==> user.getEmail();
			final JwtUser userDetails=(JwtUser) authentication.getPrincipal();
			SecurityContextHolder.getContext().setAuthentication(authentication);

			//Generating Token
			final String token=jwtTokenUtil.generateToken(userDetails);
			response.setHeader("token", token);
			return new ResponseEntity<UserDTO>(
					new UserDTO(userDetails.getUser(),
							token),
				HttpStatus.OK);


		}catch (Exception e) {
			throw new UnauthorizedException(e.getMessage());
		}
		//return null;

	}


}

/*


{
    "user": {
        "id": 1,
        "firstName": "saikumar",
        "lastName": "saikumar",
        "email": "saikumar@gmail.com",
        "password": "$2a$10$JUfRBQi6CSYqLflauAmrYO4k8dCTH6PcKGd10dQzDMn9HiRcF2Lfq",
        "enabled": true,
        "role": "ADMIN",
        "phoneNumber": "63050",
        "createdDate": "2024-01-16T04:13:03.529+0000"
    },
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzYWlrdW1hckBnbWFpbC5jb20iLCJjcmVhdGVkIjoxNzA1Mzc4NzgwNDQwLCJleHAiOjE3MDU5ODM1ODB9.rdVjUaezSgb8NbtYdvD4g4TD1UpxfD7B2pHq2TAIm2TM9J4peDdjI32ASoqLbdlb9oWomLx1p-zbS8xZl-pUOg"
}



-------------------------------------------------------------------------------------------


{
    "user": {
        "id": 2,
        "firstName": "ratna",
        "lastName": "ratna",
        "email": "ratna@gmail.com",
        "password": "$2a$10$WwJZaTqQGdfcon/KLX5..eBM42OqEGnhS2MHo2jpVQI/.Cng.vaQS",
        "enabled": true,
        "role": "USER",
        "phoneNumber": "94416",
        "createdDate": "2024-01-16T04:13:50.347+0000"
    },
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJyYXRuYUBnbWFpbC5jb20iLCJjcmVhdGVkIjoxNzA1Mzc4NzAwNDYwLCJleHAiOjE3MDU5ODM1MDB9.uYEQFi8gx3iT263L-cCckgUvdFZ9jMpk7CyrhJCwiwL_SQzkOAbjRSKzOw88luOhLYHEf30SJii7jAorMFGB1g"
}


 */