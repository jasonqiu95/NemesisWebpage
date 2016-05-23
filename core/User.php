<?php
namespace nemesis;
/**
 * All in one user object use to authenticating, registering new users and other user actions
 * Note: Either start() or login() must be called at least once on your code per User instance
 *
 * @package ptejada\uFlex
 * @author  Pablo Tejada <pablo@ptejada.com>
 */
class User extends UserBase
{
    /**
     * Class Version
     *
     * @var string
     */
    const VERSION = '1.0.6';
    /** @var DB_Table - The database table object */
    public $table;

    public $isSigned;
    /**
     * Holds a unique clone number of the instance clones
     *
     * @var int
     * @ignore
     */
    protected $clone = 0;
    /** @var DB - The database connection */
    protected $db;
    /**
     * @var array Array of errors text. Could use overwritten for multilingual support
     */
    protected $errorList = array(
        //Database Error while calling register functions
        1  => 'New User Registration Failed',
        //Database Error while calling update functions
        2  => 'The Changes Could not be made',
        //Database Error while calling activate function
        3  => 'Account could not be activated',
        //When calling pass_reset and the given email doesn't exist in database
        4  => 'We don\'t have an account with this email',
        //When calling new_pass, the confirmation hash did not match the one in database
        5  => 'Password could not be changed. The request can\'t be validated',
        6  => 'Logging with cookies failed',
        7  => 'No email or password provided',
        8  => 'Your Account has not been Activated. Check your Email for instructions',
        9  => 'Your account has been deactivated. Please contact Administrator',
        10 => 'Wrong email or password',
        //When calling check_hash with invalid hash
        11 => 'Confirmation hash is invalid',
        //Calling check_hash hash failed database match test
        12 => 'Your identification could not be confirmed',
        //When saving hash to database fails
        13 => 'Failed to save confirmation request',
        14 => 'You need to reset your password to login',
        15 => 'Can not register a new user, as user is already logged in.',
        16 => 'This Email is already in use',
        17 => 'This Username is not available',
    );

    /**
     * Validate a login
     *
     * @api
     *
     * @param string $identifier - Username or Email
     * @param string $accessToken - accessToken
     *
     * @return bool
     */
    public function validateLogin($identifier, $accessToken) {
        $this->log->channel('validate_login');
        // Start the class if is not been start yet
        $this->start();
        if ($this->isSigned) {
            $this->log->report('User is signed in');
        }

        if ($identifier && $accessToken) {
            $this->log->report('Credentials received');
        } else {
            $this->log->error(7);
            return false;
        }

        $this->log->report('Querying Database to authenticate user');
        //Query Database for user
        $userFile = $this->table->getRow(Array("email" => $identifier));
        if ($userFile && $accessToken === $userFile->accessToken && $userFile->isSigned) {
            // Fully match the user accessToken to authenticate
            $this->isSigned = true;
            $this->_data = $userFile->toArray();
            //Done
            $this->log->report('User is Logged');
            return true;
            // Clear the updates stack
        } else {
            $this->isSigned = false;
            $this->log->formError('accessToken', $this->errorList[10]);
            return false;
        }
    }

    /**
     * Login a with given credentials.
     *
     * @api
     *
     * @param string $identifier - Username or Email
     * @param string $password   - Clear text password
     *
     * @return bool
     */
    public function login($identifier, $password)
    {
        $this->log->channel('login');
        // Start the class if is not been start yet
        $this->start();
        //Session Login
        if ($this->isSigned) {
            $this->log->report('User is signed in');
        }

        //Credentials Login
        if ($identifier && $password) {
            //Login using email
            $getBy = 'email';
            $this->log->report('Credentials received');
        } else {
            $this->log->error(7);
            return false;
        }

        $this->log->report('Querying Database to authenticate user');
        //Query Database for user
        $userFile = $this->table->getRow(Array($getBy => $identifier));
        if ($userFile) {
            // Fully match the user password to authenticate
            $this->_updates = $userFile;
            /*
             * Encode the password with the hashing algorithm
             */
            $generated = $this->hash->generateUserPassword($this, $password);
            /*
             * Compared the generated hash with the stored one
             * If it matches then the user will be logged in
             */
            $this->isSigned = $generated === $userFile->password;
            // Clear the updates stack
            $this->_updates = new Collection();

            if (!$this->isSigned) {
                if ($password) {
                    $this->log->formError('password', $this->errorList[10]);
                    return false;
                }
            }

            //If Account is not Activated
            if ($userFile->activated == 0) {
                if ($userFile->lastLogin == 0) {
                    //Account has not been activated
                    $this->log->formError('password',$this->errorList[8]);
                } else {
                    if (!$userFile->confirmation) {
                        //Account has been deactivated
                        $this->log->formError('password',$this->errorList[9]);
                    } else {
                        //Account deactivated due to a password reset or reactivation request
                        $this->log->formError('password',$this->errorList[14]);
                    }
                }
                // Remove the signed flag
                $this->session->signed = 0;
                return false;
            }

            $this->_data = $userFile->toArray();
            //If auto Remember User
            //Update last_login
            $this->logLogin();
            //Done
            $this->log->report('User Logged in Successfully');
            return true;
        } else {
            if ($password) {
                $this->log->formError('password', $this->errorList[10]);
                return false;
            }
        }
    }
    /**
     * Starts and Configures the object
     *
     * @return $this
     */
    public function start()
    {
        if (!($this->db instanceof DB)) {
            // Updating the predefine error logs
            $this->log->addPredefinedError($this->errorList);
            // Instantiate the Database object
            if ($this->config->database->pdo instanceof \PDO) {
                // Uses an existing PDO connection
                $this->db = new DB($this->config->database->pdo);
            } else {
                if ($this->config->database->dsn) {
                    $this->db = new DB($this->config->database->dsn);
                } else {
                    $this->db = new DB($this->config->database->host, $this->config->database->name);
                }
                // Configure the database object
                $this->db->setUser($this->config->database->user);
                $this->db->setPassword($this->config->database->password);
            }
            // Link logs
            $this->db->log = $this->log;
            //Instantiate the table DB object
            $this->table = $this->db->getTable($this->config->userTableName);


        }
        // Link the session with the user data
        //if (is_null($this->session->data)) {
        //    $this->session->data = $this->config->userDefaultData->toArray();
        //}
        $this->_data = $this->config->userDefaultData->toArray();
        return $this;
    }
    /**
     * Logs user last login in database
     *
     * @ignore
     */
    protected function logLogin()
    {
        //Update last_login
        $time = time();
        $this->_data['accessToken'] = $this->hash->generateToken();
        $sql = "UPDATE _table_ SET lastLogin=:stamp, isSigned=:isSigned, accessToken=:accessToken WHERE id=:id";
        if ($this->table->runQuery($sql,
            array('stamp' => $time,
                'isSigned' => true,
                'accessToken' => $this->accessToken,
                'id' => $this->id))) {
            $this->log->report('Last Login updated');
        }
    }
    /**
     * Logout the user
     * Logs out the current user and deletes any autologin cookies
     *
     * @return void
     */
    function logout()
    {
        //Import default user object
        $this->_data = $this->config->userDefaultData->toArray();
        $this->log->report('User Logged out');
    }

    /**
     * Register A New User
     * Takes two parameters, the first being required
     *
     * @access public
     * @api
     *
     * @param array|Collection $info       An associative array, the index being the field name(column in database)and the value
     *                                     its content(value)
     * @param bool             $activation Default is false, if true the user will need required further steps to activate account
     *                                     Otherwise the account will be activated if registration succeeds
     *
     * @return string|bool Returns activation hash if second parameter $activation is true
     *                        Returns true if second parameter $activation is false
     *                        Returns false on Error
     */
    public function register($info, $activation = false)
    {
        $this->log->channel('registration'); //Index for Errors and Report
        //Saves Registration Data in Class
        $this->_updates = $info = $this->toCollection($info);
        //Validate All Fields
        if (!$this->validateAll(true)) {
            return false;
        } //There are validations error
        //Set Registration Date
        $info->regDate = time();
        /*
         * Built in actions for special fields
         */
        //Hash Password
        if ($info->password) {
            $info->password = $this->hash->generateUserPassword($this, $info->password);
        }
        //Check for Email in database
        if ($info->email) {
            if ($this->table->isUnique('email', $info->email, 16)) {
                return false;
            }
        }
        //Check for errors
        if ($this->log->hasError()) {
            return false;
        }
        //User Activation
        if (!$activation) {
            //Activates user upon registration
            $info->activated = 1;
        }
        //Prepare Info for SQL Insertion
        $data = array();
        $into = array();
        foreach ($info->toArray() as $index => $val) {
            if (!preg_match("/2$/", $index)) { //Skips double fields
                $into[] = $index;
                //For the statement
                $data[$index] = $val;
            }
        }
        // Construct the fields
        $intoStr = implode(', ', $into);
        $values = ':' . implode(', :', $into);
        //Prepare New User Query
        $sql = "INSERT INTO _table_ ({$intoStr})
                VALUES({$values})";
        //Enter New user to Database
        if ($this->table->runQuery($sql, $data)) {
            $this->log->report('New User has been registered');
            // Update the new ID internally
            $this->_data['id'] = $info->id = $this->table->getLastInsertedID();
            if ($activation) {
                // Generate a user specific hash
                $info->confirmation = $this->hash->generate($info->id);
                // Update the newly created user with the confirmation hash
                $this->update(array('confirmation' => $info->confirmation));
                // Return the confirmation hash
                return $info->confirmation;
            } else {
                return true;
            }
        } else {
            $this->log->error(1);
            return false;
        }
    }
    /**
     * Validates and updates any field in the database for the current user
     * Similar to the register method function in structure,
     * this Method validates and updates any field in the database
     *
     * @api
     *
     * @param array|Collection $updates An associative array,
     *                                  the index being the field name(column in database)
     *                                  and the value its content(value)
     *
     * @return bool Returns true on success anf false on error
     */
    public function update($updates = null)
    {
        $this->log->channel('update');
        if (!is_null($updates)) {
            //Saves Updates Data in Class
            $this->_updates = $updates = $this->toCollection($updates);
        } else {
            if ($this->_updates instanceof Collection && !$this->_updates->isEmpty()) {
                // Use the updates from the queue
                $updates = $this->_updates;
            } else {
                // No updates
                return false;
            }
        }
        //Validate All Fields
        if (!$this->validateAll()) {
            //There are validations error
            return false;
        }
        /*
         * Built in actions for special fields
         */
        //Hash Password
        if ($updates->password) {
            $updates->password = $this->hash->generateUserPassword($this, $updates->password);
        }
        //Check for Email in database
        if ($updates->email) {
            if ($updates->email != $this->email) {
                if ($this->table->isUnique('email', $updates->email, 'This email is already in Use')) {
                    return false;
                }
            }
        }
        //Check for errors
        if ($this->log->hasError()) {
            return false;
        }
        //Prepare Info for SQL Insertion
        $data = array();
        $set = array();
        foreach ($updates->toArray() as $index => $val) {
            if (!preg_match('/2$/', $index)) { //Skips double fields
                $set[] = "{$index}=:{$index}";
                //For the statement
                $data[$index] = $val;
            }
        }
        $set = implode(', ', $set);
        //Prepare User Update Query
        $sql = "UPDATE _table_ SET {$set}  WHERE id=:id";
        $data['id'] = $this->id;
        //Check for Changes
        if ($this->table->runQuery($sql, $data)) {
            $this->log->report('Information Updated');
            if ($this->clone === 0) {
            }
            // Update the current object with the updated information
            $this->_data = array_merge($this->_data, $updates->toArray());
            // Clear the updates stack
            $this->_updates = new Collection();
            return true;
        } else {
            $this->log->error(2);
            return false;
        }
    }
    /**
     * Method to reset password, Returns confirmation code to reset password
     *
     * @access public
     * @api
     *
     * @param string $email User email to reset password
     *
     * @return Collection|bool On Success it returns a Collection with the user's (Email,Username,ID,Confirmation)
     *                        which could then be use to construct the confirmation URL and Email.
     *                        On Failure it returns false
     */
    public function resetPassword($email)
    {
        $this->log->channel('resetPassword');
        $user = $this->table->getRow(array('Email' => $email));
        if ($user) {
            if (!$user->activated && !$user->confirmation) {
                //The Account has been manually disabled and can't reset password
                $this->log->error(9);
                return false;
            }
            $data = array(
                'id'           => $user->id,
                'confirmation' => $this->hash->generate($user->id),
            );
            $this->table->runQuery('UPDATE _table_ SET confirmation=:confirmation WHERE id=:id', $data);
            return new Collection(
                array(
                    'email'        => $email,
                    'id'           => $user->id,
                    'confirmation' => $data['confirmation']
                )
            );
        } else {
            $this->log->formError('email', $this->errorList[4]);
            return false;
        }
    }

    /**
     * Destroys the session if the instance is a clone
     */
    public function __destruct()
    {
        if ($this->clone > 0) {
        }
    }
    /**
     * Activates Account with a hash
     * Takes Only and Only the URL parameter of a confirmation page
     * which would be the hash returned by the register() method
     *
     * @access public
     * @api
     *
     * @param string $hash Hash returned in the register method
     *
     * @return bool Returns true account activation and false on failure
     */
    public function activate($hash)
    {
        $this->log->channel('activation');
        $info = $this->hash->examine($hash);
        if ($info && is_array($info)) {
            list($uid, $partial) = $info;
            $user = $this->manageUser($uid);
            if ($user->id) {
                if ($user->confirmation === $hash) {
                    $user->activated = 1;
                    $user->confirmation = '';
                    // Updates the flag on the database
                    if ($user->update()) {
                        $this->log->report('Account has been Activated');
                        return true;
                    }
                } else {
                    $this->log->report('The activation hash does not match the DB record');
                }
            } else {
                $this->log->report("Unable to find user with ID $uid to activate");
            }
        }
        /*
         * Execution will end up here if something goes wrong
         */
        $this->log->error(3);
        return false;
    }
    /**
     * Magic method to handle object cloning
     *
     * @ignore
     */
    protected function __clone()
    {
        $this->clone++;
        // Copy the configuration
        $this->config = new Collection($this->config->toArray());
        $this->_updates = new Collection();
        $this->log = $this->log->newChildLog('UserClone' . $this->clone);
        //Import default user object to session
        //Link the new session namespace to the internal data array
        $this->_data = $this->config->userDefaultData->toArray();
    }
}
