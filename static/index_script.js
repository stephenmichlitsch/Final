// This is an event listener that is waiting for the user to start typing so that we can check the password strength of the user's input
document.addEventListener('DOMContentLoaded', function() {

    // The first two vars' are grabbing the user's input in new password and update password this is tied in with the event listener so this just means they update as the user types in their input
    var updatePasswordInput = document.getElementById('update_password');
    var newPasswordInput = document.getElementById('new_password');

    // The last two vars' are the responses to the user's current input updating as the user types
    var passwordStrengthUpdate = document.getElementById('password-strength-update');
    var passwordStrengthNew = document.getElementById('password-strength-new');

    // The next two event listeners are listening for the input and then running that input through the function that will check the strenth of the uesr's password
    updatePasswordInput.addEventListener('input', function() {
        var password = updatePasswordInput.value;
        evaluatePasswordStrength(password, passwordStrengthUpdate);
    });

    newPasswordInput.addEventListener('input', function() {
        var password = newPasswordInput.value;
        evaluatePasswordStrength(password, passwordStrengthNew);
    });

    /* This is the function that checks the user's password strength via the two event listeners above 
    Now I must note that ChatGPT helped me out a bit with this because I had built a password checker in my helpers.py file and I needed to connect this to the EventListener through java I simply asked Chat if this was possible and it listed functions and I worked out the logic along with learning how the functions worked */ 
    function evaluatePasswordStrength(password, strengthElement) {
        // Send password to Flask server for the password checker
        fetch('/check_password_strength', {
            method: 'POST',
            // The code below makes sure that the python and java script are on the same page in reguard to the data being processed between client-side and server-side 
            headers: {
                // Here I set the content-type to JSON data which simply makes sure the server side knows to expect JSON data 
                'Content-Type': 'application/json',
            },
            // This sends the password via JSON string to my python code
            body: JSON.stringify({ password: password }),
        })
        /* This function I learned handles the response from the server after the fetch request is successful and data is what is returned by my python code
        So this first line takes the response from my python function and converts it into JSON with response.json() */
        .then(response => response.json())
        // Once the JSON data is retrieved we then handle the data which in this case is the strength of the password that had been submitted above
        .then(data => {
            // This concatenates the string 'Password Strength: ' with the response from my python function within the converted JSON data 
            var strengthText = 'Password Strength: ' + data.strength;
            /* This basically just updates the text content of the DOM element with the concatenated string 
            So to clarify we get the string with a var and then we place that var in the text content */ 
            strengthElement.textContent = strengthText;

            // This simply applies color to the text based on the response from the python password check function
            if (data.strength === 'Strong') {
                strengthElement.style.color = 'green';
            } else if (data.strength === 'Medium') {
                strengthElement.style.color = 'orange';
            } else {
                strengthElement.style.color = 'red';
            }
        })
        // Logs an error to the console if the fetch is not successful or any of the promises fail from the '.then' functions mostly for debugging 
        .catch(error => {
            console.error('Error:', error);
        });
    }
});