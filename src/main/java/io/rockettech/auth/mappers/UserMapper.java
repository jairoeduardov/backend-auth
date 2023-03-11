package io.rockettech.auth.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import io.rockettech.auth.dto.UserDto;
import io.rockettech.auth.entities.AuthUser;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(source = "user.id", target = "id")
    @Mapping(source = "user.login", target = "login")
    @Mapping(source = "token", target = "token")
    @Mapping(target = "password", ignore = true)
    UserDto toUserDto(AuthUser user, String token);

    @Mapping(source = "encodedPassword", target = "password")
    AuthUser toAuthUser(UserDto userDto, String encodedPassword);
}
