const google_oauth = import("./google_oauth");

google_oauth.then(oauth => {
    let client = oauth.Client("s");

    console.log(client)
})
