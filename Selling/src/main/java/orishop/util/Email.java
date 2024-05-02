package orishop.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import orishop.DAO.AccountDAOImpl;
import orishop.DAO.IAccountDAO;
import orishop.models.AccountModels;
import at.favre.lib.crypto.bcrypt.BCrypt;

public class Email {
    private static final String EMAIL_CONFIG_FILE = "config.properties";    
    private static final Logger LOGGER = Logger.getLogger(Email.class.getName());
    private IAccountDAO accountDAO = new AccountDAOImpl();

    private Properties loadEmailConfig() {
        Properties props = new Properties();
        try (InputStream input = Email.class.getClassLoader().getResourceAsStream(EMAIL_CONFIG_FILE)) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return props;
    }

    public String getRandom() {
        Random rnd = new Random();
        int number = rnd.nextInt(999999);
        return String.format("%06d", number);
    }

    public boolean sendEmail(AccountModels account) {
        boolean test = false;
        String toEmail = account.getMail();
        String fromEmail = loadEmailConfig().getProperty("email.username");
        String password = loadEmailConfig().getProperty("email.password");

        LOGGER.log(Level.INFO, "Sending email from: " + fromEmail);
        LOGGER.log(Level.INFO, "Email password: " + password);

        try {
            Properties pr = configEmail(new Properties());
            Session session = Session.getInstance(pr, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(fromEmail, password);
                }
            });
            Message mess = new MimeMessage(session);
            mess.setHeader("Content-Type", "text/plain; charset=UTF-8");
            mess.setFrom(new InternetAddress(fromEmail));
            mess.setRecipient(Message.RecipientType.TO, new InternetAddress(toEmail));

            mess.setSubject("Confirm-Code");

            mess.setText("Your is code: " + account.getCode());

            Transport.send(mess);

            test = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return test;
    }

    public boolean EmailSend(AccountModels user) {
        boolean test = false;
        String toEmail = user.getMail();
        String fromEmail = loadEmailConfig().getProperty("email.username");
        String password = loadEmailConfig().getProperty("email.password");

        LOGGER.log(Level.INFO, "Sending email from: " + fromEmail);
        LOGGER.log(Level.INFO, "Email password: " + password);
        try {
            Properties pr = configEmail(new Properties());
            Session session = Session.getInstance(pr, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(fromEmail, password);
                }
            });
            Message mess = new MimeMessage(session);
            mess.setHeader("Content-Type", "text/plain; charset=UTF-8");
            mess.setFrom(new InternetAddress(fromEmail));
            mess.setRecipient(Message.RecipientType.TO, new InternetAddress(toEmail));

            mess.setSubject("Temporary Password");

            // Generating a temporary password
            String temporaryPassword = getRandom();
            
            // Hashing the temporary password using bcrypt
            String hashedPassword = BCrypt.withDefaults().hashToString(12, temporaryPassword.toCharArray());
            
            // Setting the hashed temporary password in the database
            accountDAO.updatePassword(user.getAccountID(), hashedPassword);
            
            // Composing the email content
            StringBuilder emailContent = new StringBuilder();
            emailContent.append("Hello ").append(user.getUsername()).append(",\n\n");
            emailContent.append("You have requested a temporary password to access your account.\n\n");
            emailContent.append("Your temporary password is: ").append(temporaryPassword).append("\n\n");
            emailContent.append("Please remember to change your password after logging in.\n\n");
            emailContent.append("Best regards,\nThe Orishop Team");
            
            mess.setText(emailContent.toString());

            Transport.send(mess);

            test = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return test;
    }

    public Properties configEmail(Properties pr) {
        pr.setProperty("mail.smtp.host", "smtp.gmail.com");
        pr.setProperty("mail.smtp.port", "587");
        pr.setProperty("mail.smtp.auth", "true");
        pr.setProperty("mail.smtp.starttls.enable", "true");
        pr.put("mail.smtp.socketFactory.port", "587");
        pr.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        return pr;
    }
}
