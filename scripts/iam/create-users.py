#!/usr/bin/env python3

import boto3
import json
import os
import random
import string
import sys
import yaml

from botocore.exceptions import ClientError


def generate_password(length=12):
    """Generate a password with:
      - a lower case character
      - an upper case character
      - a digit
      - a special character
    """

    lower = random.sample(string.ascii_lowercase, 8)
    upper = random.sample(string.ascii_uppercase, 8)
    digits = random.sample(string.digits, 5)
    special = random.sample("!@#$%^&*()_+-=[]{}|'", 2)
    all_chars = lower + upper + digits + special
    random.shuffle(all_chars)
    return "".join(all_chars)[:length]


def create_user(session, login, firstname, lastname, mail, groups):
    """Create a new IAM user and add the user to the groups"""

    try:
        session.client("iam").create_user(
            UserName=login,
            Tags=[
                {"Key": "mail", "Value": mail},
                {"Key": "firstname", "Value": firstname},
                {"Key": "lastname", "Value": lastname},
            ],
        )
        print("Creating user", login)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"User {login} already exists")

    user = session.resource("iam").User(login)
    user_password = None

    # If the password has already been used by the user, do not update the profile
    # with a new password
    if user.password_last_used is None:
        profiles = user.LoginProfile()
        print("\tsetting password")
        while user_password is None:
            try:
                user_password = generate_password()
                try:
                    profiles.create(Password=user_password, PasswordResetRequired=True)
                except ClientError as e:
                    if e.response["Error"]["Code"] == "EntityAlreadyExists":
                        profiles.update(
                            Password=user_password, PasswordResetRequired=True
                        )
            except ClientError as e:
                if e.response["Error"]["Code"] == "PasswordPolicyViolation":
                    user_password = None

    # Add the user to the groups
    for group in groups:
        print("\tgroup:", group)
        user.add_group(GroupName=group, UserName=login)

    # Export user info to a <login>.json file
    with open(f"{login}.json", "w", encoding="utf8") as f:
        f.write(
            json.dumps(
                {
                    "user": f"{firstname} {lastname}",
                    "login": login,
                    "password": user_password,
                    "mail": mail,
                    "groups": list(groups),
                },
                ensure_ascii=False,
                indent=2,
            )
        )


def create_tech_user(session, login, firstname, lastname, mail, groups):
    """Create a new IAM user and add the user to the groups"""

    try:
        session.client("iam").create_user(
            UserName=login,
            Tags=[
                {"Key": "mail", "Value": mail},
                {"Key": "firstname", "Value": firstname},
                {"Key": "lastname", "Value": lastname},
            ],
        )
        print("Creating user", login)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"User {login} already exists")

    user = session.resource("iam").User(login)

    # Add the user to the groups
    for group in groups:
        print("\tgroup:", group)
        user.add_group(GroupName=group, UserName=login)

    try:
        accessKey = session.client("iam").create_access_key(UserName=login)

        # Export user info to a <login>.json file
        with open(f"{login}.json", "w", encoding="utf8") as f:
            f.write(
                json.dumps(
                    {
                        "user": f"{firstname} {lastname}",
                        "mail": mail,
                        "groups": list(groups),
                        "UserName": accessKey["AccessKey"]["UserName"],
                        "AccessKeyId": accessKey["AccessKey"]["AccessKeyId"],
                        "SecretAccessKey": accessKey["AccessKey"]["SecretAccessKey"],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
    except ClientError as e:
        if e.response["Error"]["Code"] == "LimitExceeded":
            print(f"Access key limit access achived for tech user {login}")


def main(filename):
    users = None
    # Load the yaml file
    with open(filename, "r") as f:
        users = yaml.load(f)

    # Create a session using AWS_PROFILE environment variable
    session = boto3.session.Session(profile_name=os.environ.get("AWS_PROFILE"))

    for user in users.get("Users", []):
        create_user(
            session=session,
            login=user["Login"],
            firstname=user["FirstName"],
            lastname=user["LastName"],
            mail=user["Mail"],
            groups=set(users["CommonGroups"] + user["Groups"]),
        )
    for tech in users.get("TechnicalUsers", []):
        create_tech_user(
            session=session,
            login=tech["Login"],
            firstname=tech["FirstName"],
            lastname=tech["LastName"],
            mail=tech["Mail"],
            groups=set(tech["Groups"]),
        )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s new-users.yml" % sys.argv[0])
        sys.exit(0)
    main(sys.argv[1])
