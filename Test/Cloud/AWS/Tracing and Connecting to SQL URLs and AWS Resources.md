### Title: Tracing and Connecting to SQL URLs and AWS Resources

### Steps to Follow

1. **SQL Connection Attempts**
   - Try to connect to the SQL database URLs.

2. **Trace Variables in Terraform**
   - Trace the variables from the Terraform definitions to the Terraform files in the GitHub repositories.
   - Ensure this traces both the SQL and AWS credentials.

3. **Script Execution Time**
   - Ran the script at 5:15 PM.

4. **AWS S3 Bucket Operations**
   - Get S3 buckets from `us-east-1`.
   - Try to connect to `us-east-2`.
   - Note: `us-east-1` has no public EC2 instances to connect to.
   - Note: `us-west-1` has no public EC2 instances to connect to.
   - Continue pulling S3 buckets.

5. **Key File Discovery**
   - Found a PEM file:
     ```
     ABCD-zlop1-lightbulbcloud\ABCD-zlop1-lightbulbcloud\ServiceNowToSailpoint\NSGSNOWGroupsPrivateK.pem
     ```

6. **Next Steps**
   - Try out the PEM file for further operations.