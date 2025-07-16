
use storage explorer

1. Download and install Azure Storage Explorer from the official Microsoft website: [https://azure.microsoft.com/en-us/features/storage-explorer/](https://azure.microsoft.com/en-us/features/storage-explorer/)
    
2. Launch Azure Storage Explorer after installation.
    
3. Click on the "Add an account" button in the toolbar.
    
4. Select "Use a shared access signature (SAS) URI" and click "Next".
    
5. Enter the following information:
    
    - Display ne: Provide a ne for your storage account.
    - Account Kind: Select "StorageV2 (general purpose v2)".
    - URI: Leave it blank for now.
6. Click on the "Next" button.
    
7. Enter the following information:
    
    - Account ne: Enter your storage account ne (e.g., "dcsmdpstorageacc").
    - Account Key: Enter your storage account key.
    - Use HTTPS: Check this option.
8. Click on the "Next" button.
    
9. Review the summary and click on the "Connect" button.
    
10. Once connected, you will see your storage account listed in the left-hand pane.
    
11. Expand the storage account and navigate to the "Blob Containers" section.
    
12. Locate and select the "dataextract" container.
    
13. You will now see the blobs within the "dataextract" container in the right-hand pane.
    
14. To download a specific blob, right-click on the blob and select "Download" from the context menu. Choose the destination folder to save the blob.
    
15. To upload a file to the "dataextract" container, right-click on the container and select "Upload" from the context menu. Choose the file you want to upload.
    
16. You can perform other operations such as deleting blobs or creating new blobs within the "dataextract" container using the options available in Azure Storage Explorer.