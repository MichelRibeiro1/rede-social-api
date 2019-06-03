<?php

use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;
use Firebase\JWT\JWT;

return function (App $app) {
    $container = $app->getContainer();

    $app->get('/', function (Request $request, Response $response, array $args) use ($container) {
        return $container->get('renderer')->render($response, 'index.phtml', $args);
    });

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
        $user = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
        return $this->response->withJson($user);
    });

    $app->get("/search/user", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
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
        $mappedUsers = array_map(function ($user) {
            $query = $this->db->prepare("SELECT status
                FROM relations
                WHERE deleted = 0
                AND (user_id IN (:userId, :targetId) OR target_id IN (:userId, :targetId))
                AND status != 'canceled'
            ");
            $query->bindParam(":userId", $me->{'id'});
            $query->bindParam(":targetId", $user["id"]);
            $query->execute();
            $relation = $query->fetch();

            if ($relation !== false){
                $user["relation_status"] = $relation["status"];
            } else {
                $user["relation_status"] = null;
            }
            return $user;
        }, $users);
        return $this->response->withJson($mappedUsers);
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

    $app->get("/users/{userId}/timeline", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
        $query = $this->db->prepare("SELECT 
            u.id as userId,
            u.profile_img_url as user_img_url,
            u.name as user_name,
            p.content_text as content,
            p.content_img as post_img,
            p.created_at as post_created_at,
            p.id as post_id
            FROM posts p
            LEFT JOIN users u
            ON p.user_id = u.id
            WHERE p.user_id = :userId
            AND p.deleted = 0
            ORDER BY p.created_at DESC;
        ");
        $query->bindParam(":userId", $args["userId"]);
        $query->execute();
        $posts = $query->fetchAll();

        $postsMapped = array_map(function ($post){
            $query = $this->db->prepare("SELECT COUNT(id) as count FROM post_likes
                WHERE post_id = :postId
                AND deleted = 0
            ");
            $query->bindParam(":postId", $post["post_id"]);
            $query->execute();
            $likes_count = $query->fetch();

            $query = $this->db->prepare("SELECT
                u.id as userId,
                u.name as user_name,
                u.profile_img_url as user_img,
                pc.content as user_comment,
                pc.created_at as created_at
                FROM post_comments as pc
                LEFT JOIN users u
                ON pc.user_id = u.id
                WHERE pc.post_id = :postId
                AND pc.deleted = 0
                AND u.deleted = 0
            ");

            $query->bindParam(":postId", $post["post_id"]);
            $query->execute();
            $comments = $query->fetchAll();

            $post["comments_count"] = sizeof($comments);
            $post["comments"] = $comments;
            $post["likes_count"] = $likes_count["count"];
            return $post;
        }, $posts);

        return $this->response->withJson($postsMapped);
    });

    $app->get("/users/{userId}/invite", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }

        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
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

    $app->get("/me/invitations/{invitationId}/reject", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));

        $query = $this->db->prepare("UPDATE relations
            SET status = 'canceled'
            WHERE id = :id
        ");

        $query->bindParam(":id", $args["invitationId"]);
        $query->execute();

        return $this->response->withStatus(200);
    });

    $app->get("/me/friends/{userId}/cancel", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));

        $query = $this->db->prepare("UPDATE relations
            SET status = 'canceled'
            WHERE status = 'accepted'
            AND (userId IN (:userId, :meId) OR targetId IN (:userId, :meId))
            AND deleted = 0
        ");

        $query->bindParam(":userId", $args["userId"]);
        $query->bindParam(":meId", $me->{'id'});
        $query->execute();

        return $this->response->withStatus(200);
    });

    $app->get("/me/invitations", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));

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
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));

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
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));

        $query = $this->db->prepare("SELECT
            u.id as id,
            u.name as name,
            u.email as email,
            u.description as description,
            u.profile_img_url as img_url
            FROM relations r
            LEFT JOIN users u
            ON r.user_id = u.id OR r.target_id = u.id
            WHERE (r.user_id = :userId OR r.target_id = :userId)
            AND (u.deleted = 0 AND r.deleted = 0 AND status = 'accepted')
            AND u.id != :userId
        ");

        $query->bindParam(":userId", $me->{'id'});
        $query->execute();
        $friends = $query->fetchAll();

        return $this->response->withJson($friends);
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

        $jwt = JWT::encode($token, getenv("SECRET_KEY"));
            return $response->withJson(["auth-jwt" => $jwt], 200)
                ->withHeader('Content-type', 'application/json');   
    });

    $app->map(["GET", "POST"], "/me/posts", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
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
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
        
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

    $app->get("/me/timeline", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
        
        $query = $this->db->prepare("SELECT 
                u.id as userId,
                u.profile_img_url as user_img_url,
                u.name as user_name,
                p.content_text as content,
                p.content_img as post_img,
                p.created_at as post_created_at,
                p.id as post_id
                FROM posts p
                LEFT JOIN users u
                ON p.user_id = u.id
                WHERE (user_id IN (
                SELECT u.id
                FROM relations r
                LEFT JOIN users u
                ON r.user_id = u.id OR r.target_id = u.id
                WHERE (r.user_id = :userId OR r.target_id = :userId)
                AND (u.deleted = 0 AND r.deleted = 0 AND status = 'accepted')
                AND u.id != :userId
            ) OR user_id = :userId ) AND p.deleted = 0 ORDER BY p.created_at DESC;
        ");

        $query->bindParam(":userId", $me->{'id'});
        $query->execute();
        $posts = $query->fetchAll();

        $postsMapped = array_map(function ($post){
            $query = $this->db->prepare("SELECT COUNT(id) as count FROM post_likes
                WHERE post_id = :postId
                AND deleted = 0
            ");
            $query->bindParam(":postId", $post["post_id"]);
            $query->execute();
            $likes_count = $query->fetch();

            $query = $this->db->prepare("SELECT
                u.id as userId,
                u.name as user_name,
                u.profile_img_url as user_img,
                pc.content as user_comment,
                pc.created_at as created_at
                FROM post_comments as pc
                LEFT JOIN users u
                ON pc.user_id = u.id
                WHERE pc.post_id = :postId
                AND pc.deleted = 0
                AND u.deleted = 0
            ");

            $query->bindParam(":postId", $post["post_id"]);
            $query->execute();
            $comments = $query->fetchAll();

            $post["comments_count"] = sizeof($comments);
            $post["comments"] = $comments;
            $post["likes_count"] = $likes_count["count"];
            return $post;
        }, $posts);

        return $this->response->withJson($postsMapped);
    });

    $app->map(["POST", "DELETE"], "/posts/{postId}/like", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));

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

    $app->post("/posts/{postId}/comment", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
        $input = $request->getParsedBody();
        $query = $this->db->prepare("INSERT INTO post_comments (id, post_id, user_id, content, created_at) VALUES (
            :id,
            :postId,
            :userId,
            :content,
            NOW()
        )");

        $query->bindParam(":id", uniqid());
        $query->bindParam(":postId", $args["postId"]);
        $query->bindParam(":userId", $me->{'id'});
        $query->bindParam(":content", $input["content"]);
        $query->execute();

        return $this->response->withStatus(200);
    });

    $app->delete("/posts/{postId}/comment/{commentId}", function (Request $request, Response $response, array $args) use ($container) {
        $headers = $request->getHeaders();
        if (!isset($headers["HTTP_X_TOKEN"])) {
            return $this->response->withStatus(403);
        }
        $me = JWT::decode($headers["HTTP_X_TOKEN"][0], getenv("SECRET_KEY"), array('HS256'));
        $input = $request->getParsedBody();

        $query = $this->db->prepare("UPDATE post_comments
            SET deleted = 1
            WHERE user_id = :userId
            AND post_id = :postId
            AND id = :commentId
            AND deleted = 0
        ");

        $likeQuery->bindParam(":userId", $me->{'id'});
        $likeQuery->bindParam(":postId", $args["postId"]);
        $likeQuery->bindParam(":commentId", $args["commentId"]);
        $likeQuery->execute();

        return $this->response->withStatus(200);
    });
};
