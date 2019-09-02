function assumeRole() {
    ROLE_ARN=$1
    CREDS="$(aws sts assume-role --role-arn "${ROLE_ARN}" --role-session-name wrap-aws)"

    unset AWS_PROFILE

    AWS_ACCESS_KEY_ID="$(     echo "${CREDS}" | jq -r .Credentials.AccessKeyId )"
    AWS_SECRET_ACCESS_KEY="$( echo "${CREDS}" | jq -r .Credentials.SecretAccessKey )"
    AWS_SECURITY_TOKEN="$(    echo "${CREDS}" | jq -r .Credentials.SessionToken )"
    AWS_SESSION_TOKEN="$(     echo "${CREDS}" | jq -r .Credentials.SessionToken )"

    export AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY
    export AWS_SECURITY_TOKEN
    export AWS_SESSION_TOKEN
}

