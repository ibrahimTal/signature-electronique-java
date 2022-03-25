package ma.amiharbi;

import javax.xml.bind.DatatypeConverter;
import java.lang.reflect.Array;
import java.util.Arrays;

public class Test1 {
    public static void main(String[] args) {
        String document = "ceci est mon message";
        byte[] bytes = document.getBytes();
        System.out.println(Arrays.toString(bytes));
        System.out.println(DatatypeConverter.printHexBinary(bytes));
    }
}