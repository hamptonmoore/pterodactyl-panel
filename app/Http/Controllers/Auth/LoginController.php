<?php

namespace Pterodactyl\Http\Controllers\Auth;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Contracts\View\View;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Database\Eloquent\ModelNotFoundException;

class LoginController extends AbstractLoginController
{
    private ViewFactory $view;

    private \League\OAuth2\Client\Provider\GenericProvider $provider;

    /**
     * LoginController constructor.
     */
    public function __construct(ViewFactory $view)
    {
        parent::__construct();

        $this->provider = config('auth.provider');

        $this->view = $view;
    }

    /**
     * Handle all incoming requests for the authentication routes and render the
     * base authentication view component. Vuejs will take over at this point and
     * turn the login area into a SPA.
     */
    public function index(): View
    {
        return $this->view->make('templates/auth.core');
    }

    /**
     * Handle a login request to the application.
     *
     * @return \Illuminate\Http\JsonResponse|void
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
        } catch (ModelNotFoundException $exception) {
            $this->sendFailedLoginResponse($request);
        }

        // Ensure that the account is using a valid username and password before trying to
        // continue. Previously this was handled in the 2FA checkpoint, however that has
        // a flaw in which you can discover if an account exists simply by seeing if you
        // can proceede to the next step in the login process.
        if (!password_verify($request->input('password'), $user->password)) {
            $this->sendFailedLoginResponse($request, $user);
        }

        if ($user->use_totp) {
            $token = Str::random(64);

            $request->session()->put('auth_confirmation_token', [
                'user_id' => $user->id,
                'token_value' => $token,
                'expires_at' => CarbonImmutable::now()->addMinutes(5),
            ]);

            return new JsonResponse([
                'data' => [
                    'complete' => false,
                    'confirmation_token' => $token,
                ],
            ]);
        }

        $this->auth->guard()->login($user, true);

        return $this->sendLoginResponse($user, $request);
    }

    public function oauthredirect(Request $request): \Illuminate\Http\RedirectResponse
    {

        $options = [
            'scope' => ['openid','email', "profile"]
        ];
        $url = $this->provider->getAuthorizationUrl($options);
        session(['state' => $this->provider->getState()]);
        return redirect($url);
    }

    public function oauthcallback(Request $request) 
    {
        if (empty($_GET['state']) || null == session('state') || $_GET['state'] !== session('state')) {
            echo session("state");
            if (null !== session('state')) {
                $request->session()->forget('state');
            }

            return redirect("/");
        }

        $accessToken = $this->provider->getAccessToken('authorization_code', [
            'code' => $_GET['code'],
            'scope' => ['openid','email', "profile"]
        ]);
        $d = json_decode(base64_decode(str_replace('_', '/', str_replace('-','+',explode('.', $accessToken)[1]))));
        $username = $d->sub;

        try {
            $user = User::query()->where($this->getField($username), $username)->firstOrFail();
        } catch (ModelNotFoundException $exception) {
            return redirect("/");
        }

        $this->auth->guard()->login($user, true);
        return redirect("/");
    }
}
