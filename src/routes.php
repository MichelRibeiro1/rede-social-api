<?php

use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;
use Firebase\JWT\JWT;

return function (App $app) {
    $container = $app->getContainer();

    $app->get("/me", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $user = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));
        return $this->response->withJson($user);
    });

    $app->get("/search/user", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $params = $request->getQueryParams();
        $userQuery = $this->db->prepare("SELECT id, name, email, profile_img_url, description
            FROM users
            WHERE deleted = 0
            AND name LIKE CONCAT('%', :name, '%')
        ");
        $userQuery->bindParam(":name", $params["name"]);
        $userQuery->execute();
        $users = $userQuery->fetchAll();

        return $this->response->withJson($users);
    });

    $app->map(["GET", "POST"], "/users/{userId}", function (Request $request, Response $response, array $args) use ($container) {
        if ($request->isPost()) {
            $input = $request->getParsedBody();
            $id = uniqid();
            $password = md5($input["password"]);
            $userQuery = $this->db->prepare("SELECT * FROM users WHERE deleted = 0 AND email = :email");
            $userQuery->bindParam(":email", $input["email"]);
            $userQuery->execute();
            $user = $userQuery->fetch();

            if ($user !== false) {
                $body = $this->response->getBody();
                $body->write('Email em uso');
                return $this->response->withStatus(409);
            }

            $sth = $this->db->prepare("INSERT INTO users (id, name, email, profile_img_url, description, deleted, created_at, password) VALUES (
                    :id,
                    :name,
                    :email,
                    :profile_img_url,
                    :description,
                    false,
                    NOW(),
                    :password

                )");
            $sth->bindParam(":id", $id);
            $sth->bindParam(":name", $input["name"]);
            $sth->bindParam(":email", $input["email"]);
            $sth->bindParam(":profile_img_url", $input["profile_img_url"]);
            $sth->bindParam(":description", $input["description"]);
            $sth->bindParam(":password", $password);
            $sth->execute(); 

            return $this->response->withStatus(200);
        } else {
            $headers = $request->getHeaders();
            if (!isset($headers["HTTP_X_TOKEN"])) {
                return $this->response->withStatus(403);
            }
            $user = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));
            return $this->response->withJson($user);
        }
    });

    $app->post("/auth", function (Request $request, Response $response, array $args) use ($container) {
        $input = $request->getParsedBody();

        if(!isset($input["email"]) or !isset($input["password"])) {
            $body = $this->response->getBody();
            $body->write('Informe senha e email');
            return $this->response->withStatus(400);
        }

        $hash = md5($input["password"]);
        $userQuery = $this->db->prepare("SELECT name, email, profile_img_url, description
            FROM users
            WHERE deleted = 0
            AND email = :email
            AND password = :password
        ");

        $userQuery->bindParam(":email", $input["email"]);
        $userQuery->bindParam(":password", $hash);
        $userQuery->execute();

        $user = $userQuery->fetch();

        if ($user === false) {
            $body = $this->response->getBody();
            $body->write('Email e/ou senha inválido');
            return $this->response->withStatus(401);
        }

        $token = array(
            "email" => $user["email"],
            "name" => $user["name"],
            "description" => $user["description"],
            "profile_img_url" => $user["profile_img_url"]
        );

        $jwt = JWT::encode($token, "chave_secreta");
            return $response->withJson(["auth-jwt" => $jwt], 200)
                ->withHeader('Content-type', 'application/json');   
    });
};
