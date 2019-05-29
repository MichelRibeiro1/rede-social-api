<?php

use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;
use Firebase\JWT\JWT;

return function (App $app) {
    $container = $app->getContainer();

    $app->get("/ping", function(Request $request, Response $response, array $args) use ($container) {
        $body = $this->response->getBody();
        $body->write("PONG");
        return $this->response->withStatus(200);
    });

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
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));
        $params = $request->getQueryParams();
        $userQuery = $this->db->prepare("SELECT id, name, email, profile_img_url, description
            FROM users
            WHERE deleted = 0
            AND id != :id
            AND name LIKE CONCAT('%', :name, '%')
        ");
        $userQuery->bindParam(":name", $params["name"]);
        $userQuery->bindParam(":id", $me->{'id'});
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
            $query = $this->db->prepare("SELECT name, email, profile_img_url, description
                FROM users
                WHERE id = :userId
                AND deleted = 0
            ");
            $query->bindParam(":userId", $args["userId"]);
            $query->execute();
            $user = $query->fetch();

            return $this->response->withJson($user);
        }
    });

    $app->get("/users/{userId}/invite", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }

        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));
        $query = $this->db->prepare("SELECT * FROM relations
            WHERE user_id IN (:userId, :targetId)
            AND target_id IN (:userId, :targetId)
            AND deleted = 0
            AND status IN ('pending', 'accepted')
        ");
        $query->bindParam(":userId", $me->{'id'});
        $query->bindParam(":targetId", $args["userId"]);
        $query->execute();
        $invitation = $query->fetch();

        if ($invitation !== false) {
            return $this->response->withStatus(409);
        }
        $id = uniqid();
        $query = $this->db->prepare("INSERT INTO relations (id, user_id, target_id, created_at) VALUES (
            :id,
            :userId,
            :targetId,
            NOW()
        )
        ");

        $query->bindParam(":id", $id);
        $query->bindParam(":userId", $me->{'id'});
        $query->bindParam(":targetId", $args["userId"]);
        $query->execute();

        return $this->response->withStatus(200);

    });

    $app->get("/users/{userId}/invite/cancel", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));

        $query = $this->db->prepare("UPDATE relations
            SET status = 'canceled'
            WHERE user_id = :userId
            AND target_id = :targetId
            AND deleted = 0
        ");

        $query->bindParam(":userId", $me->{'id'});
        $query->bindParam(":targetId", $args["userId"]);
        $query->execute();

        return $this->response->withStatus(200);
    });

    $app->get("/me/invitations", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));

        $query = $this->db->prepare("SELECT
            r.id invitation_id,
            u.name sender_name,
            u.id sender_id,
            u.profile_img_url target_img_url
        FROM relations r
        LEFT JOIN users u
        ON r.user_id = u.id
        WHERE r.deleted = 0
        AND status = 'pending'
        AND u.deleted = 0
        AND r.target_id = :userId
        ");

        $query->bindParam(":userId", $me->{'id'});
        $query->execute();
        $invitations = $query->fetchAll();
        return $this->response->withJson($invitations);
    });

    $app->get("/me/invitations/{invitationId}/accept", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));

        $query = $this->db->prepare("UPDATE relations
            SET status = 'accepted'
            WHERE id = :invitationId
            AND target_id = :userId
            AND deleted = 0
        ");

        $query->bindParam(":invitationId", $args["invitationId"]);
        $query->bindParam(":userId", $me->{'id'});
        $query->execute();

        return $this->response->withStatus(200);
    });

    $app->get("/me/friends", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));

        $query = $this->db->prepare("SELECT
            u.id user_id,
            name,
            email,
            description,
            profile_img_url
            FROM relations r
            LEFT JOIN users u
            ON r.user_id = u.id AND r.target_id = u.id -- TODO: Use this with With statement
            -- WHERE (user_id = :userId OR target_id = :userId) AND (deleted = 0 AND status = 'accepted')
        ");

        $query->bindParam(":userId", $me->{'id'});
        $query->bindParam(":userId", $me->{'id'});
        $query->execute();

        return $this->response->withStatus(200);
    });

    $app->post("/auth", function (Request $request, Response $response, array $args) use ($container) {
        $input = $request->getParsedBody();

        if(!isset($input["email"]) or !isset($input["password"])) {
            $body = $this->response->getBody();
            $body->write('Informe senha e email');
            return $this->response->withStatus(400);
        }

        $hash = md5($input["password"]);
        $userQuery = $this->db->prepare("SELECT id, name, email, profile_img_url, description
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
            "id" => $user["id"],
            "name" => $user["name"],
            "description" => $user["description"],
            "profile_img_url" => $user["profile_img_url"]
        );

        $jwt = JWT::encode($token, "chave_secreta");
            return $response->withJson(["auth-jwt" => $jwt], 200)
                ->withHeader('Content-type', 'application/json');   
    });

    $app->map(["GET", "POST"], "/me/posts", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));
        $id = uniqid();
        if ($request->isPost()) {
            $input = $request->getParsedBody();
            $query = $this->db->prepare("INSERT INTO posts (id, content_text, content_img, user_id, created_at) VALUES (
                :id,
                :content_text,
                :content_img,
                :user_id,
                NOW()
            )");
            $query->bindParam(":id", $id);
            $query->bindParam(":content_text", $input["text"]);
            $query->bindParam(":content_img", $input["img"]);
            $query->bindParam(":user_id", $me->{'id'});
            $query->execute();

            return $this->response->withStatus(200);
        } else {
            $query = $this->db->prepare("SELECT * FROM posts
                WHERE user_id = :userId
                AND deleted = 0
            ");
            $query->bindParam(":userId", $me->{'id'});
            $query->execute();

            $posts = $query->fetchAll();

            return $this->response->withJson($posts);
        }
    });

    $app->delete("/me/posts/{postId}", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));
        
        $query = $this->db->prepare("UPDATE posts
            SET deleted = 1
            WHERE user_id = :userId
            AND id = :postId
            AND deleted = 0
        ");

        $query->bindParam(":userId", $me->{'id'});
        $query->bindParam(":postId", $args["postId"]);
        $query->execute();

        return $this->response->withStatus(200);
    });

    $app->map(["POST", "DELETE"], "/posts/{postId}/like", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], "chave_secreta", array('HS256'));

        if ($request->isPost()) {
            $query = $this->db->prepare("SELECT * FROM post_likes
                WHERE user_id = :userId
                AND post_id = :postId
                AND deleted = 0
            ");

            $query->bindParam(":userId", $me->{'id'});
            $query->bindParam(":postId", $args["postId"]);
            $query->execute();
            $like = $query->fetch();

            if ($like !== false) {
                $body = $this->response->getBody();
                $body->write('Já curtido');
                return $this->response->withStatus(409);
            }

            $likeQuery = $this->db->prepare("INSERT INTO post_likes (id, post_id, user_id, created_at) VALUES (
                :id,
                :postId,
                :userId,
                NOW()
            )");

            $likeQuery->bindParam(":id", uniqid());
            $likeQuery->bindParam(":userId", $me->{'id'});
            $likeQuery->bindParam(":postId", $args["postId"]);
            $likeQuery->execute();

            return $this->response->withStatus(200);
        } else {
            $query = $this->db->prepare("UPDATE post_likes
                SET deleted = 1
                WHERE user_id = :userId
                AND post_id = :postId
                AND deleted = 0
            ");


            $query->bindParam(":userId", $me->{'id'});
            $query->bindParam(":postId", $args["postId"]);
            $query->execute();

            return $this->response->withStatus(200);
        }
    });
};
