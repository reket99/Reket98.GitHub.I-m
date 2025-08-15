List Files  


buckets=$(aws s3api list-buckets --query "Buckets[].Name" --output text)
echo "["  # start JSON array
first_bucket=true
for b in $buckets; do
    # Get up to 100 objects for this bucket
    objects=$(aws s3api list-objects-v2 --bucket "$b" --max-items 100 \
        --query "Contents[].{Bucket:\`$b\`,Key:Key,Size:Size,LastModified:LastModified,StorageClass:StorageClass}" \
        --output json 2>/dev/null)

    # Skip if empty or inaccessible
    if [[ -z "$objects" || "$objects" == "null" ]]; then
        continue
    fi

    # Comma between arrays
    if [[ "$first_bucket" == false ]]; then
        echo ","
    fi
    first_bucket=false

    # Print JSON for this bucket
    echo "$objects"
done
echo "]"  # end JSON array
