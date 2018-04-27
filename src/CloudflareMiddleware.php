<?php namespace Tuna;

use Exception;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use function GuzzleHttp\Psr7\modify_request;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

class CloudflareMiddleware
{
    /**
     * WAIT_RESPONSE_CODE this is the response code which Cloudflare throws when UAM is active
     */
    const WAIT_RESPONSE_CODE = 503;

    /**
     * SERVER_NAME name of the server which Cloudflare uses
     */
    const SERVER_NAME = [
        'cloudflare-nginx',
        'cloudflare'
    ];

    /**
     * REFRESH_EXPRESSION regular expression used to parse the 'Refresh' header
     */
    const REFRESH_EXPRESSION = '/8;URL=(\/cdn-cgi\/l\/chk_jschl\?pass=[0-9]+\.[0-9]+-.*)/';

    /** @var callable */
    protected $nextHandler;

    /** @var string|null */
    protected $nodePath;

    /** @var string|null */
    protected $nodeModulesPath;

    /**
     * @param callable $nextHandler Next handler to invoke.
     * @param string|null $nodePath path to node executable, default null (use global node)
     * @param string|null @nodeModulesPath path to nodemodules with installed browser-env and sandbox.js, default null (use global modules)
     */
    public function __construct(callable $nextHandler, $nodePath = null, $nodeModulesPath = null)
    {
        $this->nextHandler = $nextHandler;
        $this->nodePath = $nodePath;
        $this->nodeModulesPath = $nodeModulesPath;
    }

    /**
     * @param string|null $nodePath path to node executable, default null (use global node)
     * @param string|null @nodeModulesPath path to nodemodules with installed browser-env and sandbox.js, default null (use global modules)
     * @return \Closure
     */
    public static function create($nodePath = null, $nodeModulesPath = null)
    {
        return function ($handler) use($nodePath, $nodeModulesPath)
        {
            return new static($handler, $nodePath, $nodeModulesPath);
        };
    }

    /**
     * @param \Psr\Http\Message\RequestInterface $request
     * @param array $options
     * @return \Psr\Http\Message\RequestInterface
     */
    public function __invoke(RequestInterface $request, array $options = [])
    {
        $next = $this->nextHandler;

        return $next($request, $options)
            ->then(
                function (ResponseInterface $response) use ($request, $options) {
                    return $this->checkResponse($request, $options, $response);
                }
            );
    }

    /**
     * @param \Psr\Http\Message\RequestInterface $request
     * @param array $options
     * @param \Psr\Http\Message\ResponseInterface $response
     * @return \Psr\Http\Message\RequestInterface|\Psr\Http\Message\ResponseInterface
     * @throws \Exception
     */
    protected function checkResponse(RequestInterface $request, array $options = [], ResponseInterface $response)
    {
        if (!$this->needVerification($response)) {
            return $response;
        }

        if (empty($options['cookies'])) {
            throw new Exception('you have to use cookies');
        }

        if (empty($options['allow_redirects'])) {
            throw new Exception('you have to use the allow_redirects options');
        }

        return $this($this->modifyRequest($request, $response), $options);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @return bool
     */
    protected function needVerification(ResponseInterface $response)
    {
        return $response->getStatusCode() === static::WAIT_RESPONSE_CODE
            && in_array($response->getHeaderLine('Server'), static::SERVER_NAME, true);
    }

    /**
     * @param \Psr\Http\Message\RequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface $response
     * @return \Psr\Http\Message\RequestInterface
     * @throws \Exception
     */
    protected function modifyRequest(RequestInterface $request, ResponseInterface $response)
    {
        return modify_request(
            $request,
            [
                'uri' => UriResolver::resolve(
                    $request->getUri(),
                    $this->getRefreshUri($request, $response)
                ),
                'body' => '',
                'method' => 'GET',
                'set_headers' => [
                    'Referer' => $request->getUri()->withUserInfo('', ''),
                ],
            ]
        );
    }

    /**
     * @param \Psr\Http\Message\RequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface $response
     * @return \GuzzleHttp\Psr7\Uri
     * @throws \Exception
     */
    protected function getRefreshUri(RequestInterface $request, ResponseInterface $response)
    {
        if (preg_match(static::REFRESH_EXPRESSION, $response->getHeaderLine('Refresh'), $matches)) {
            return new Uri($matches[1]);
        }

        return $this->solveJavascriptChallenge($request, $response);
    }

    /**
     * Try to solve the JavaScript challenge
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface $response
     * @return \GuzzleHttp\Psr7\Uri
     * @throws \Exception
     */
    protected function solveJavascriptChallenge(RequestInterface $request, ResponseInterface $response)
    {
        $content = $response->getBody();
        $script = 
<<<SCRIPT
require('browser-env')({url: '{$request->getUri()}'});
var sandbox = require('sandbox.js'),
    console_log = function(o){console.log(o);},
    context = {require: require, DOMParser: DOMParser, document: document, HTMLFormElement: HTMLFormElement, CustomEvent: CustomEvent, window: window, setTimeout: setTimeout, location: location, console_log: console_log},
    code = function(){
(function(){
    var parser = new DOMParser(),
        content = 'text/html',
        divElement = document.createElement('div'),
        form
    ;
    divElement.setAttribute('id', 'cf-content');
    document.body.appendChild(divElement);
    HTMLFormElement.prototype.submit = function(){
        var params = [];
        for(var el of this.elements) {
            params.push(encodeURIComponent(el.name)+ '=' + encodeURIComponent(el.value));
        }
        params.push('f=1')
        this.action += '?' + params.join('&');
        var event = new CustomEvent("submit", {detail: this.action});
        this.dispatchEvent(event);
    };
    {$this->findForms($content)}
})();
{$this->findScripts($content)};
(function(){var event = new CustomEvent("DOMContentLoaded", {});document.dispatchEvent(event);})();
}
;
sandbox.runInSandbox(code, context);
SCRIPT;

        $tmpFile = tmpfile();
        fwrite($tmpFile, $script);
        fflush($tmpFile);

        $meta_data = stream_get_meta_data($tmpFile);
        $filename = $meta_data["uri"];

        $process = new Process($this->getProcessPath($filename));

        try 
        {
            $process->mustRun();

            return new Uri($process->getOutput());
        } 
        catch (ProcessFailedException $e) 
        {
            throw new \ErrorException(sprintf('Something went wrong! Please report an issue: %s', $e->getMessage()));
        }
    }

    /**
     * Find all forms from content
     * @param string $content 
     * @return string
     */
    private function findForms($content)
    {
        $matches = [];
        $forms = [];
        preg_match_all('/<form.*?id="(?P<form_id>[\w-]+)".*?<\/form>/s', $content, $matches);
        foreach($matches[0] as $_i => $_form) {
            $_form = addslashes(str_replace(["\r", "\n"], '', $_form));
            array_push(
                $forms,
<<<FORM
form = parser.parseFromString("{$_form}", content).body.childNodes[0];
divElement.appendChild(form);
document.getElementById("{$matches['form_id'][$_i]}").addEventListener("submit", function(e){console_log(e.detail)});
FORM
            );
        }
        return join("\n", $forms);
    }

    /**
     * Find all scripts from content
     * @param string $content 
     * @return string
     */
    private function findScripts($content)
    {
        $matches = [];
        $scripts = [];
        preg_match_all('/<script.*?>(?P<script>.+?)<\/script>/s', $content, $matches);
        foreach($matches['script'] as $_script) {
            array_push($scripts, $_script);
        }
        return join(";\n", $scripts);
    }

    /**
     * @param string $scipt path to script
     */
    protected function getProcessPath($scipt)
    {
        $nodeModules = '';
        if(null !== $this->nodeModulesPath) {
            $nodeModules = sprintf('NODE_PATH=%s ', $this->nodeModulesPath);
        }

        if(null === $node = $this->nodePath) {
            $node = 'node';
        }
        return sprintf('%s%s %s', $nodeModules, $node, $scipt);
    }
}
