```
const selectElement = document.querySelector('#label');
if (selectElement) {
    const values = Array.from(selectElement.options).map(opt => opt.value).join('\n');
    console.log(values);
    // Optionally, if you want to copy to clipboard directly
    navigator.clipboard.writeText(values).then(() => {
        console.log('Values copied to clipboard!');
    }, err => {
        console.error('Failed to copy values: ', err);
    });
} else {
    console.log('Select element with ID "label" not found');
}

```