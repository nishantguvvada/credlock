use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use dotenv::dotenv;
use mongodb::{
    Client, Collection,
    bson::{doc, oid::ObjectId},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::error::Error;
use tokio;
use uuid::Uuid;

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

    let added_user = add_user(new_user).await;
    match added_user {
        Ok(value) => match value.inserted_id.as_object_id() {
            Some(id) => {
                HttpResponse::Ok().json(json!({"response":"User created!", "user_id": id.to_hex()}))
            }
            None => HttpResponse::NotFound()
                .json(json!({"error": "Failed to get inserted_id as ObjectId"})),
        },
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

    let new_credentials = credentials.into_inner();
    HttpResponse::Ok().json(json!({"response":new_credentials}))
}

async fn connection() -> mongodb::Client {
    dotenv().ok();

    let mongo_uri = env::var("MONGO_URI").expect("You must set MONGO_URI environment variable!");

    let client = Client::with_uri_str(mongo_uri).await;

    let result = match client {
        Ok(client_value) => client_value,
        Err(_) => panic!(),
    };

    return result;
}

async fn add_credentials(
    user_input: Credentials,
) -> Result<mongodb::results::InsertOneResult, mongodb::error::Error> {
    let client = connection().await;

    let coll: Collection<Credentials> = client.database("credlock").collection("credentials");

    let res = coll.insert_one(user_input).await;

    return res;
}

async fn add_user(
    user_details: Users,
) -> Result<mongodb::results::InsertOneResult, mongodb::error::Error> {
    let client = connection().await;

    let coll: Collection<Users> = client.database("credlock").collection("users");

    let res = coll.insert_one(user_details).await;

    return res;
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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
