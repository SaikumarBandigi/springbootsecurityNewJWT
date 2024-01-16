package com.springboot.jwt.intercepter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springboot.jwt.security.JwtTokenUtil;

public class AuthenticationTokenFilter extends OncePerRequestFilter {

	@Autowired private UserDetailsService userDetailsService;

	@Autowired private JwtTokenUtil jwtTokenUtil;

	@Value("${jwt.header}")
	private String tokenHeader; //Authorization


	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain)
			throws ServletException, IOException {

		String authToken=request.getHeader(this.tokenHeader);

		//authToken ==bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI3dG84and0YWRtaW5AZ21haWwuY29tIiwiY3JlYXRlZCI6MTU5MzQ4MzM4MjU0NCwiZXhwIjoxNTk0MDg4MTgyfQ.c7PcD9HumwzFYapYQEPx3eTKnADX8NaAMSMlBGha_HlbtzkMNbxV8bkggbke_iLXibCPkuSHB0N09h52XovSGQ
		if(authToken!=null && authToken.length()>7) {


			//KeYname="Authorization";
			//value="bearer <Token>"
			authToken=authToken.substring(7);
		}

		//Extracting the UserName from Token
		String userName=jwtTokenUtil.getUserNameFromToken(authToken);

		//If username != null and no seesion is attached with the username ==> ONly for first when token is sent
		if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null )
		{
			//SecurityContextHolder.getContext() ==> Session1 ==> JSESSIONID1
			//SecurityContextHolder.getContext() ==> Session2 ==> JSESSIONID2
			//SecurityContextHolder.getContext()  ==> ADD authentication ==> Session3 ==> JSESSIONID3
			//Doing database lookup and creating userdetails object
			UserDetails userDetails=this.userDetailsService.loadUserByUsername(userName);
			//VErifying the token is valid or not
			boolean isValid=jwtTokenUtil.validateToken(authToken,userDetails);
			if(isValid)
			{
				//Creating Authentication Object and setting to the security context
				UsernamePasswordAuthenticationToken authentication=new
						UsernamePasswordAuthenticationToken(userDetails,
								null,userDetails.getAuthorities());

				authentication.setDetails(new WebAuthenticationDetailsSource().
						buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}
		filterChain.doFilter(request, response);
	}

}
