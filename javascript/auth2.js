// The client ID is obtained from the {{ Google Cloud Console }}
// at {{ https://cloud.google.com/console }}.
// If you run this code from a server other than http://localhost,
// you need to register your own client ID.
// var OAUTH2_CLIENT_ID = '__YOUR_CLIENT_ID__';
var OAUTH2_SCOPES = [
  'https://www.googleapis.com/auth/youtube',
  'https://www.googleapis.com/auth/youtube.upload'
];

var auth2; // The Sign-In object.
var googleUser; // The current user.


/**
 * Calls startAuth after Sign in V2 finishes setting up.
 */
var appStart = function() {
  gapi.load('auth2', initSigninV2);
};

/**
 * Initializes Signin v2 and sets up listeners.
 */
var initSigninV2 = function() {
  auth2 = gapi.auth2.init({
      client_id: OAUTH2_CLIENT_ID,
      scope: OAUTH2_SCOPES.join(' ')
  });

  // Listen for sign-in state changes.
  // auth2.isSignedIn.listen(signinChanged);

  // Listen for changes to current user.
  // auth2.currentUser.listen(userChanged);

  // Sign in the user if they are currently signed in.
  // if (auth2.isSignedIn.get() != true) {
    // auth2.signIn();
  // }

  
  // Start with the current live values.
  // refreshValues();
  window.setTimeout(checkAuth, 1);
};

(function() {
/**
 * Listener method for sign-out live value.
 *
 * @param {boolean} val the updated signed out state.
 */
var signinChanged = function (val) {
  console.log('Signin state changed to ', val);
  // document.getElementById('signed-in-cell').innerText = val;
};


/**
 * Listener method for when the user changes.
 *
 * @param {GoogleUser} user the updated user.
 */
var userChanged = function (user) {
  console.log('User now: ', user);
  googleUser = user;
  updateGoogleUser();
  /*
  document.getElementById('curr-user-cell').innerText =
    JSON.stringify(user, undefined, 2);
    */
};


/**
 * Updates the properties in the Google User table using the current user.
 */
var updateGoogleUser = function () {
  if (googleUser) {
    console.log(googleUser.getId());
    console.log(googleUser.getGrantedScopes());
    console.log(JSON.stringify(googleUser.getAuthResponse(), undefined, 2));
  } else {
    console.log('no googleUser');
  }
};


/**
 * Retrieves the current user and signed in states from the GoogleAuth
 * object.
 */
var refreshValues = function() {
  if (auth2){
    console.log('Refreshing values...');

    googleUser = auth2.currentUser.get();

    console.log(JSON.stringify(googleUser, undefined, 2));
    console.log(auth2.isSignedIn.get());

    updateGoogleUser();
  }
}
});

// Attempt the immediate OAuth 2.0 client flow as soon as the page loads.
// If the currently logged-in Google Account has previously authorized
// the client specified as the OAUTH2_CLIENT_ID, then the authorization
// succeeds with no user intervention. Otherwise, it fails and the
// user interface that prompts for authorization needs to display.
function checkAuth() {
  authRes = auth2.currentUser.get().getAuthResponse(true);
  handleAuthResult(authRes);
}

// Handle the result of a gapi.auth.authorize() call.
function handleAuthResult(authResult) {
  if (authResult && !authResult.error) {
    // Authorization was successful. Hide authorization prompts and show
    // content that should be visible after authorization succeeds.
    $('.pre-auth').hide();
    $('.post-auth').show();
    loadAPIClientInterfaces(authResult);
  } else {
    // Make the #login-link clickable. Attempt a non-immediate OAuth 2.0
    // client flow. The current function is called when that flow completes.
    $('#login-link').click(function() {
      auth2.signIn().then((res) => {
        loadAPIClientInterfaces(res);
      }).catch((e) => {
        console.log('signIn: ok: ', e);
      });
    });
  }
}

// Load the client interfaces for the YouTube Analytics and Data APIs, which
// are required to use the Google APIs JS client. More info is available at
// https://developers.google.com/api-client-library/javascript/dev/dev_jscript#loading-the-client-library-and-the-api
function loadAPIClientInterfaces(authResult) {
  gapi.client.load('youtube', 'v3', function() {
    handleAPILoaded(authResult);
  });
}
