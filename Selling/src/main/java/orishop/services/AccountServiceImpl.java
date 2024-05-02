package orishop.services;

import java.util.List;

import orishop.DAO.IAccountDAO;
import orishop.DAO.AccountDAOImpl;
import orishop.models.AccountModels;
import at.favre.lib.crypto.bcrypt.BCrypt;

public class AccountServiceImpl implements IAccountService {
    private final IAccountDAO userDAO = new AccountDAOImpl();

    @Override
    public List<AccountModels> findAll() {
        return userDAO.findAll();
    }

    @Override
    public AccountModels findOne(int id) {
        return userDAO.findOne(id);
    }

    @Override
    public AccountModels findOne(String username) {
        return userDAO.findOne(username);
    }

    @Override
    public void insert(AccountModels model) {
        // Hash the password before inserting into the database
        String hashedPassword = hashPassword(model.getPassword());
        model.setPassword(hashedPassword);
        userDAO.insert(model);
    }

    @Override
    public void insertregister(AccountModels model) {
        // Hash the password before inserting into the database
        String hashedPassword = hashPassword(model.getPassword());
        model.setPassword(hashedPassword);
        userDAO.insertregister(model);
    }

    @Override
    public void update(AccountModels model) {
        userDAO.update(model);
    }

    @Override
    public void updatestatus(AccountModels model) {
        userDAO.updatestatus(model);
    }

    @Override
    public boolean register(String username, String password, String mail, String code) {
        if (userDAO.checkExistEmail(mail))
            return false;
        if (userDAO.checkExistUsername(username))
            return false;
        // Hash the password before registering
        String hashedPassword = hashPassword(password);
        userDAO.insertregister(new AccountModels(username, hashedPassword, mail, 1, 0, code));
        return true;
    }

    @Override
    public AccountModels login(String username, String password) {
        AccountModels user = this.findOne(username);
        if (user != null) {
            // Verify password using bcrypt
            if (BCrypt.verifyer().verify(password.toCharArray(), user.getPassword()).verified) {
                return user;
            }
        }
        return null;
    }

    @Override
    public boolean checkExistUsername(String username) {
        return userDAO.checkExistUsername(username);
    }

    @Override
    public boolean checkExistEmail(String mail) {
        return userDAO.checkExistEmail(mail);
    }

    @Override
    public void delete(int id) {
        userDAO.delete(id);
    }

    // Helper method to hash password using bcrypt
    private String hashPassword(String password) {
        return BCrypt.withDefaults().hashToString(12, password.toCharArray());
    }
}
