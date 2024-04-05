package com.kafka.carusers.utils;

public class AccountUtils {
    public  static  final String ACCOUNT_EXISTS_CODE ="001";
    public  static  final String ACCOUNT_NOT_EXIST_CODE ="003";
    public  static  final String ACCOUNT_EXITS_MESSAGE ="This user already exists";
    public  static  final String ACCOUNT_NOT_EXIT_MESSAGE ="This user does not exist";
    public  static  final String ACCOUNT_CREATION_SUCCESS = "002";
    public  static  final String ACCOUNT_CREATION_MESSAGE = "Account has been created successfully";
    public static  final  String TRANSFER_SUCCESSFUL_CODE = "008";
    public static  final  String TRANSFER_SUCCESSFUL_MESSAGE = "Transfer Successful";
    public static  final  String ACCOUNT_UPDATED_SUCCESS = "010";
    public static  final  String ACCOUNT_UPDATED_MESSAGE = "Account Updated Successfully";
    public static  final  String PASSWORD_FORGOT_MAIL_CODE = "011";

    public static  final  String PASSWORD_FORGOT_MAIL_MESSAGE = "Password reset successful kindly check your email";
    public static  final  String PASSWORD_CHANGED_SUCCESS ="012";
    public static  final  String PASSWORD_CHANGED_MESSAGE = "User password successfully changed";
    public static  final  String UPDATE_PASSWORD_SUCCESS = "013";
    public static  final  String UPDATE_PASSWORD_SUCCESS_MESSAGE="Your password is successfully updated";
    public static  final  String PASSWORD_DO_NOT_MATCH = "014";
    public static  final  String PASSWORD_DO_NOT_MATCH_MESSAGE = "Password does not match confirm password";
    public static  final  String USER_NOT_LOGGED_IN = "015";

    public static  final  String USER_NOT_LOGGED_IN_MESSAGE = "User not logged in";
    public  static  final String EVENT_WITH_USERS_SUCCESS ="016";
    public  static  final String EVENT_WITH_USERS_SUCCESS_MESSAGE ="Event and users fetched successfully";
    public static  final  String FETCH_ALL_USERS_SUCCESSFUL_CODE = "017";
    public static  final  String FETCH_ALL_USERS_SUCCESSFUL_MESSAGE = "All users fetched Successful";

    public static boolean validatePassword(String password, String cpassword) {
        return password.equals(cpassword);
    }



}
