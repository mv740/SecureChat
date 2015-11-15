package codebase;

/**
 * Created by micha on 11/15/2015.
 */
public class User {

    public static int getUser(boolean IsA) {
        return boolToInt(IsA);
    }

    //http://stackoverflow.com/questions/3793650/convert-boolean-to-int-in-java
    private static int boolToInt(boolean b) {
        return Boolean.compare(b, false);
    }
}
