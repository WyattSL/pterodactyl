<?php

namespace Pterodactyl\Http\Controllers\Auth;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Facades\Activity;
use Illuminate\Contracts\View\View;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Database\Eloquent\ModelNotFoundException;

class LoginController extends AbstractLoginController
{
    /**
     * LoginController constructor.
     */
    public function __construct(private ViewFactory $view)
    {
        parent::__construct();
    }

    /**
     * Handle all incoming requests for the authentication routes and render the
     * base authentication view component. React will take over at this point and
     * turn the login area into an SPA.
     */
    public function index(): View
    {
        if ($request->hasHeader("X-authentik-username")) {
            // Hey, we're authenticated!
            try {
                $username = $request->header("X-authentik-username");
                $user = User::query()->where($this->getField($username), $username)->firstOrFail();
                // Update existing credentials.
                $email = $request->header("X-authentik-email", $user->email);
                $name = $request->header("X-authentik-name", $user->getNameAttribute())
                $uid = $request->header("X-authentik-uid", $user->external_id);
                $fn = explode(" ", $name)[0];
                $ln = explode(" ", $name)[1];
                $data = [
                    'email' => $email,
                    'first_name' => $fn,
                    'last_name' => $ln,
                    'uid' => $uid,
                ];
                UserUpdateService::handle($user, $data);
                return $this->sendLoginResponse($user, $request);
            } catch (ModelNotFoundException $e) {
                // Make a new account.
                $email = $request->header("X-authentik-email", $user->email);
                $name = $request->header("X-authentik-name", $user->getNameAttribute())
                $uid = $request->header("X-authentik-uid", $user->external_id);
                $username = $request->header("X-authentik-username");
                $data = [
                    'email' => $email,
                    'first_name' => $fn,
                    'last_name' => $ln,
                    'uid' => $uid,
                    'username' => $username,
                ];
                $user = UserCreationsService::handle($data);
                return $this->sendLoginResponse($user, $request);
            }
        }
        return $this->view->make('templates/auth.core');
    }

    /**
     * Handle a login request to the application.
     *
     * @throws \Pterodactyl\Exceptions\DisplayException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request): JsonResponse
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            $this->sendLockoutResponse($request);
        }

        try {
            $username = $request->input('user');

            /** @var \Pterodactyl\Models\User $user */
            $user = User::query()->where($this->getField($username), $username)->firstOrFail();
        } catch (ModelNotFoundException) {
            $this->sendFailedLoginResponse($request);
        }

        // Ensure that the account is using a valid username and password before trying to
        // continue. Previously this was handled in the 2FA checkpoint, however that has
        // a flaw in which you can discover if an account exists simply by seeing if you
        // can proceed to the next step in the login process.
        if (!password_verify($request->input('password'), $user->password)) {
            $this->sendFailedLoginResponse($request, $user);
        }

        if (!$user->use_totp) {
            return $this->sendLoginResponse($user, $request);
        }

        Activity::event('auth:checkpoint')->withRequestMetadata()->subject($user)->log();

        $request->session()->put('auth_confirmation_token', [
            'user_id' => $user->id,
            'token_value' => $token = Str::random(64),
            'expires_at' => CarbonImmutable::now()->addMinutes(5),
        ]);

        return new JsonResponse([
            'data' => [
                'complete' => false,
                'confirmation_token' => $token,
            ],
        ]);
    }
}
