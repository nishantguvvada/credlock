use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use chrono::{Duration, Utc};
use dotenv::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use mongodb::{Client, Collection, bson::doc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (e.g., user ID)
    exp: usize,  // Expiration timestamp
}

#[derive(Debug, Deserialize, Serialize)]
struct Credentials {
    user_id: Uuid,
    secret_name: String,
    secret_value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Users {
    user_name: String,
    user_email: String,
    credential_count: u32,
}

#[get("/")]
async fn default() -> impl Responder {
    println!("default endpoint");
    HttpResponse::Ok().json(json!({"response":"on"}))
}

#[post("/users")]
async fn create_user(user: web::Json<Users>) -> impl Responder {
    let new_user = user.into_inner();
    let secret = env::var("JWT_SECRET").expect("You must set JWT_SECRET environment variable!");

    println!("user email: {}", &new_user.user_email);

    if let Ok(Some(user)) = existing_user(&new_user.user_email).await {
        println!("response: {:?}", user);
        return HttpResponse::InternalServerError()
            .json(json!({"error": format!("Already an existing user, try signing in!")}));
    }

    let added_user = add_user(&new_user).await;
    match added_user {
        Ok(value) => {
            let claim = Claims {
                sub: new_user.user_email,
                exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
            };
            let token = match encode(
                &Header::default(),
                &claim,
                &EncodingKey::from_secret(secret.as_ref()),
            ) {
                Ok(t) => t,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .json(json!({"error": format!("Token encoding failed: {}", e)}));
                }
            };

            match value.inserted_id.as_object_id() {
                Some(id) => HttpResponse::Ok().json(
                    json!({"response":"User created!", "user_id": id.to_hex(), "token": token}),
                ),
                None => HttpResponse::NotFound()
                    .json(json!({"error": "Failed to get inserted_id as ObjectId"})),
            }
        }
        Err(error) => HttpResponse::InternalServerError()
            .json(json!({"error": format!("Failed to create user: {}", error)})),
    }
}

#[post("/creds")]
async fn create_credentials(
    credentials: web::Json<Credentials>,
    auth: BearerAuth,
) -> impl Responder {
    let token = auth.token();
    println!("Received bearer token: {}", token);

    let secret = env::var("JWT_SECRET").expect("You must set JWT_SECRET environment variable!");

    let token = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(token_data) => {
            let claims = token_data.claims;
            println!("Token - User Payload : {}", claims.sub);
            claims.sub
        }
        Err(e) => {
            eprintln!("Token decoding failed: {}", e);
            return HttpResponse::Unauthorized()
                .json(json!({"error": format!("Token decoding failed: {}", e)}));
        }
    };

    if let Ok(None) = existing_user(&token).await {
        return HttpResponse::InternalServerError()
            .json(json!({"error": format!("Incorrect Token!")}));
    }

    let new_credentials = credentials.into_inner();

    let added_credentials = add_credentials(&new_credentials).await;
    match added_credentials {
        Ok(value) => {
            match value.inserted_id.as_object_id() {
                Some(id) => {
                    return HttpResponse::Ok()
                        .json(json!({"response":"Credentials stored!", "job_id": id.to_hex()}));
                }
                None => {
                    return HttpResponse::NotFound()
                        .json(json!({"error": "Failed to get inserted_id as ObjectId"}));
                }
            };
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(json!({"error": format!("Credentials upload failed: {}", e)}));
        }
    }
}

async fn connection() -> mongodb::Client {
    let mongo_uri = env::var("MONGO_URI").expect("You must set MONGO_URI environment variable!");

    let client = Client::with_uri_str(mongo_uri).await;

    let result = match client {
        Ok(client_value) => client_value,
        Err(_) => panic!(),
    };

    return result;
}

async fn existing_user(user_details: &String) -> Result<Option<Users>, mongodb::error::Error> {
    let client = connection().await;

    let coll: Collection<Users> = client.database("credlock").collection("users");

    let res = coll.find_one(doc! {"user_email": &user_details}).await;

    return res;
}

async fn add_credentials(
    user_input: &Credentials,
) -> Result<mongodb::results::InsertOneResult, mongodb::error::Error> {
    let client = connection().await;

    let coll: Collection<Credentials> = client.database("credlock").collection("credentials");

    let res = coll.insert_one(user_input).await;

    return res;
}

async fn add_user(
    user_details: &Users,
) -> Result<mongodb::results::InsertOneResult, mongodb::error::Error> {
    let client = connection().await;

    let coll: Collection<Users> = client.database("credlock").collection("users");

    let res = coll.insert_one(user_details).await;

    return res;
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    HttpServer::new(|| {
        App::new()
            .service(default)
            .service(create_user)
            .service(create_credentials)
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await
}
