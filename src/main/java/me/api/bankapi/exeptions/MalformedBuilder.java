package me.api.bankapi.exeptions;

/**
 *
 * An exception which is thrown when RevolutAPI has not been built properly.
 * Usually it happens on lack of properties.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
public class MalformedBuilder extends Exception {

    /**
     * Constructor of an exception
     *
     * @param message message of the exception to be thrown
     */
    public MalformedBuilder(String message) {
        super(message);
    }
}
