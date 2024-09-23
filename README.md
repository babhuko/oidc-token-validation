# oidc-token-validation


AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().build();
AssumeRoleRequest roleRequest = new AssumeRoleRequest()
        .withRoleArn("arn:aws:iam::123456789012:role/YourRole")
        .withRoleSessionName("sessionName");
AssumeRoleResult roleResponse = stsClient.assumeRole(roleRequest);

Credentials sessionCredentials = roleResponse.getCredentials();

BasicSessionCredentials awsCredentials = new BasicSessionCredentials(
        sessionCredentials.getAccessKeyId(),
        sessionCredentials.getSecretAccessKey(),
        sessionCredentials.getSessionToken());

AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
        .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
        .build();
