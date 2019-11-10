from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, ForeignKey, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from getpass import getpass
from hashlib import sha256 as SHA256
from secrets import token_hex
from datetime import datetime

# First the declarative base we'll be working from.
BASE = declarative_base()
DBFILE = "users.db"

def setup_db():
    global BASE
    engine = create_engine(f'sqlite:///{DBFILE}')
    BASE.metadata.bind = engine
    # Before doing this, clean up prev DB for testing purposes.
    # Submit to autograder WITHOUT this line.
    BASE.metadata.drop_all(engine)
    # Create DB again.
    BASE.metadata.create_all(engine)
    DBSessionMaker = sessionmaker(bind=engine)
    return DBSessionMaker

class User(BASE):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    uname = Column(String(25), nullable=False, unique=True)
    pword = Column(String(64), nullable=False)
    salt = Column(String(16), nullable=False)

class LoginRecord(BASE):
    __tablename__ = 'login_records'
    record_number =  Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    time_on = Column(DateTime, nullable=False)
    user = relationship(User)

def register(session):
    # Get username and password.
    uname = input("Username: ")
    pword = getpass("Password: ")
    hasher = SHA256()
    # Add password to hash algorithm.
    hasher.update(pword.encode('utf-8'))
    # Generate random salt.
    salt = token_hex(nbytes=16)
    # Add random salt to hash algorithm.
    hasher.update(salt.encode('utf-8'))
    # Get the hex of the hash.
    pword_store = hasher.hexdigest()
    # Store the new user in the database.
    new_user = User(uname=uname, pword=pword_store, salt=salt)
    session.add(new_user)
    # Probably want error handling, etc. For this simplified code,
    # we're assuming all is well.
    session.commit()

def login(session):
    uname = input("Username: ")
    pword = getpass("Password: ")
    hasher = SHA256()
    # Get the user we're attempting to log in as.
    user_record = session.query(User).filter(User.uname == uname).first()
    # Grab their salt.
    salt = user_record.salt
    # Add password and salt to hasher.
    hasher.update(pword.encode('utf-8'))
    hasher.update(salt.encode('utf-8'))
    # Get hex digest.
    password_hash = hasher.hexdigest()
    # Confirm that the credentials are correct.
    if(password_hash == user_record.pword):
        # Log this login.
        login_record = LoginRecord(user_id=user_record.user_id, time_on=datetime.now())
        session.add(login_record)
        session.commit()
        # return success.
        return True, user_record
    # Auth failed.
    return False

def main():
    # Set up our database.
    DBSessionMaker = setup_db()
    # Grab a database session.
    session = DBSessionMaker()
    logged_in_user = None
    while True:
        mode = int(input("1. Register\n2. Login\n3. Quit\nChoice: "))
        if mode == 1:
            register(session)
        elif mode == 2:
            success, logged_in_user = login(session)
            if success:
                print(f"You are now logged in as {logged_in_user.uname}.")
            else:
                print("Login failed.")
        elif mode == 3:
            session.close()
            break
        else:
            continue

if __name__ == '__main__':
    main()
