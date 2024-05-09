use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use actix_cors::Cors;
use jsonwebtoken::{encode, Header, EncodingKey};
use mongodb::{Client, Database, Collection};
use bson::{doc, Document};
use futures::stream::TryStreamExt;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_id: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthToken {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    sender_id: String,
    receiver_id: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
    email: String,
    phone: usize
    // Add more fields as needed, such as email, name, etc.
}

async fn signup(user: web::Json<User>, db: web::Data<Database>) -> impl Responder {
    // Check if the username already exists
    let collection = db.collection("users");
    let existing_user = collection
        .find_one(doc! {"username": &user.username}, None)
        .await
        .unwrap();

    match existing_user {
        Some(_) => HttpResponse::Conflict().body("Username already exists"),
        None => {
            // Insert the new user into the database
            let user_doc = bson::to_document(&*user).unwrap();
            collection.insert_one(user_doc, None).await.unwrap();
            HttpResponse::Created().body("User created successfully")
        }
    }
}

async fn get_users(db: web::Data<Database>) -> impl Responder {
    let collection: Collection<Document> = db.collection("users");
    let mut cursor = collection.find(None, None).await.unwrap();

    let mut users = Vec::new();
    while let Some(result) = cursor.try_next().await.unwrap() {
        if let Some(user) = bson::from_document::<User>(result).ok() {
            users.push(user);
        }
    }

    HttpResponse::Ok().json(users)
}

async fn login(req: web::Json<LoginRequest>, db: web::Data<Database>) -> impl Responder {
    // Check credentials against database
    let collection: Collection<Document> = db.collection("users");
    let query = doc! {"username": &req.username, "password": &req.password};
    let user = collection.find_one(query, None).await.unwrap();

    match user {
        Some(user_doc) => {
            let user_id = user_doc.get_object_id("_id").unwrap().to_hex();
            let expiry = 3600; // Token expiry time in seconds
            let claims = Claims { user_id, exp: expiry };

            // Create JWT token
            let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
            let jwt_secret = EncodingKey::from_secret(jwt_secret.as_bytes());
            let token = encode(&Header::default(), &claims, &jwt_secret).unwrap();
            HttpResponse::Ok().json(AuthToken { token })
        }
        None => HttpResponse::Unauthorized().finish(),
    }
}

async fn send_message(
    message: web::Json<Message>,
    db: web::Data<Database>,
) -> impl Responder {
    let collection = db.collection("messages");
    let message_doc = bson::to_document(&*message).unwrap();
    collection.insert_one(message_doc, None).await.unwrap();
    HttpResponse::Ok().finish()
}

async fn get_messages(
    user_id: web::Path<String>,
    db: web::Data<Database>,
) -> impl Responder {
    let collection: mongodb::Collection<Document> = db.collection("messages");
    let query = doc! {"receiver_id": &*user_id};
    let mut cursor = collection.find(query, None).await.unwrap();
    let mut messages = Vec::new();

    while let Some(result) = cursor.try_next().await.unwrap() {
    messages.push(result);
    }

    HttpResponse::Ok().json(messages)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let host = "localhost:8000";
    println!("Starting server at {}", host);

    let client = Client::with_uri_str("mongodb://localhost:27017/").await.unwrap();
    let db = client.database("chat_app");

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin("http://localhost:3000") // Replace with your frontend URL
                    .allowed_methods(vec!["GET", "POST"]) // Specify allowed methods
                    .allowed_headers(vec!["Content-Type"]) // Specify allowed headers
                    .supports_credentials() // Enable credentials support
            )
            .app_data(web::Data::new(db.clone()))
            .service(web::resource("/signup").route(web::post().to(signup)))
            .route("/", web::get().to(get_users))
            .route("/login", web::post().to(login))
            .route("/send_message", web::post().to(send_message))
            .route("/get_messages/{user_id}", web::get().to(get_messages))
    })
    .bind(host)?
    .run()
    .await
}
