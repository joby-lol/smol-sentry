<?php

namespace Joby\Smol\Sentry;

use Joby\Smol\Sentry\InspectionRules\InspectionRule;
use Joby\Smol\Sentry\InspectionRules\RequestData;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class InspectorTest extends TestCase
{

    protected MockObject&Sentry $sentry;

    protected Inspector $inspector;

    protected function setUp(): void
    {
        $this->sentry = $this->createMock(Sentry::class);
        $this->inspector = new Inspector($this->sentry);
    }

    // Signal routing

    public function test_no_rules_fires_no_signal(): void
    {
        $this->sentry->expects($this->never())->method('signal');
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_malicious_rule_fires_malicious_signal(): void
    {
        $this->sentry->expects($this->once())
            ->method('signal')
            ->with('Inspector: test_rule', Severity::Malicious);
        $this->inspector->addRule('test_rule', $this->mockRule(Severity::Malicious));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_suspicious_rule_fires_suspicious_signal(): void
    {
        $this->sentry->expects($this->once())
            ->method('signal')
            ->with('Inspector: test_rule', Severity::Suspicious);
        $this->inspector->addRule('test_rule', $this->mockRule(Severity::Suspicious));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_null_rule_fires_no_signal(): void
    {
        $this->sentry->expects($this->never())->method('signal');
        $this->inspector->addRule('test_rule', $this->mockRule(null));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    // Evaluation order and short-circuiting

    public function test_malicious_stops_evaluation_of_later_rules(): void
    {
        $this->sentry->expects($this->once())
            ->method('signal')
            ->with('Inspector: first', Severity::Malicious);
        $this->inspector->addRule('first', $this->mockRule(Severity::Malicious));
        $this->inspector->addRule('second', $this->mockRule(Severity::Malicious, should_be_called: false));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_malicious_preempts_earlier_suspicious(): void
    {
        $this->sentry->expects($this->once())
            ->method('signal')
            ->with('Inspector: malicious_one', Severity::Malicious);
        $this->inspector->addRule('suspicious_one', $this->mockRule(Severity::Suspicious));
        $this->inspector->addRule('malicious_one', $this->mockRule(Severity::Malicious));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_multiple_suspicious_fires_only_first(): void
    {
        $this->sentry->expects($this->once())
            ->method('signal')
            ->with('Inspector: first_sus', Severity::Suspicious);
        $this->inspector->addRule('first_sus', $this->mockRule(Severity::Suspicious));
        $this->inspector->addRule('second_sus', $this->mockRule(Severity::Suspicious));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_suspicious_continues_evaluation_looking_for_malicious(): void
    {
        $this->sentry->expects($this->once())
            ->method('signal')
            ->with('Inspector: malicious_one', Severity::Malicious);
        $this->inspector->addRule('suspicious_one', $this->mockRule(Severity::Suspicious));
        $this->inspector->addRule('clean_one', $this->mockRule(null));
        $this->inspector->addRule('malicious_one', $this->mockRule(Severity::Malicious));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_all_null_fires_no_signal(): void
    {
        $this->sentry->expects($this->never())->method('signal');
        $this->inspector->addRule('a', $this->mockRule(null));
        $this->inspector->addRule('b', $this->mockRule(null));
        $this->inspector->addRule('c', $this->mockRule(null));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    // Rule management

    public function test_add_rule_returns_inspector_for_chaining(): void
    {
        $result = $this->inspector->addRule('test', $this->mockRule(null));
        $this->assertSame($this->inspector, $result);
    }

    public function test_add_rule_overwrites_existing_name(): void
    {
        $this->sentry->expects($this->never())->method('signal');
        $this->inspector->addRule('rule', $this->mockRule(Severity::Malicious, should_be_called: false));
        $this->inspector->addRule('rule', $this->mockRule(null));
        $this->inspector->inspect(
            SERVER: ['REQUEST_URI' => '/'],
            GET: [],
            POST: [],
            FILES: [],
            COOKIE: [],
        );
    }

    public function test_add_default_rules_adds_expected_rules(): void
    {
        $this->inspector->addDefaultRules();
        $this->assertArrayHasKey('path_manipulation', $this->inspector->rules);
        $this->assertArrayHasKey('restricted_files', $this->inspector->rules);
        $this->assertArrayHasKey('malicious_user_agents', $this->inspector->rules);
    }

    // Helpers

    protected function mockRule(Severity|null $returns, bool $should_be_called = true): InspectionRule
    {

        return new class ($returns, $should_be_called) implements InspectionRule {

            public function __construct(
            private Severity|null $returns,
            private bool $should_be_called,
            ) {}

            public function check(RequestData $request): Severity|null
            {
                if (!$this->should_be_called)
                    throw new \RuntimeException('Rule should not have been called');
                return $this->returns;
            }

        };
    }

    // flatten()

    public function test_flatten_simple_array(): void
    {
        $result = Inspector::flatten(['a' => 'one', 'b' => 'two']);
        $this->assertEquals(['a' => 'one', 'b' => 'two'], $result);
    }

    public function test_flatten_nested_array(): void
    {
        $result = Inspector::flatten(['a' => ['b' => 'one', 'c' => 'two']]);
        $this->assertEquals(['a/b' => 'one', 'a/c' => 'two'], $result);
    }

    public function test_flatten_deeply_nested_array(): void
    {
        $result = Inspector::flatten(['a' => ['b' => ['c' => 'deep']]]);
        $this->assertEquals(['a/b/c' => 'deep'], $result);
    }

    public function test_flatten_handles_integer_keys(): void
    {
        $result = Inspector::flatten([0 => 'zero', 1 => 'one']);
        $this->assertEquals(['0' => 'zero', '1' => 'one'], $result);
    }

    public function test_flatten_handles_key_collisions(): void
    {
        $result = Inspector::flatten([
            'a/b' => 'first',
            'a'   => ['b' => 'second'],
        ]);
        $this->assertCount(2, $result);
        $this->assertEquals('first', $result['a/b']);
        $this->assertEquals('second', $result['a/b_']);
    }

    public function test_flatten_casts_scalars_to_string(): void
    {
        $result = Inspector::flatten(['int' => 42, 'bool' => true, 'float' => 3.14]);
        $this->assertSame('42', $result['int']);
        $this->assertSame('1', $result['bool']);
        $this->assertSame('3.14', $result['float']);
    }

    public function test_flatten_throws_on_non_scalar(): void
    {
        $this->expectException(\RuntimeException::class);
        Inspector::flatten(['bad' => new \stdClass()]);
    }

    public function test_flatten_empty_array(): void
    {
        $result = Inspector::flatten([]);
        $this->assertEquals([], $result);
    }

    // flattenFiles()

    public function test_flatten_files_simple(): void
    {
        $files = [
            'upload' => [
                'name'     => 'photo.jpg',
                'type'     => 'image/jpeg',
                'tmp_name' => '/tmp/xyz',
                'error'    => 0,
                'size'     => 12345,
            ],
        ];
        $this->assertEquals(['photo.jpg'], Inspector::flattenFiles($files));
    }

    public function test_flatten_files_multiple_inputs(): void
    {
        $files = [
            'avatar' => [
                'name'     => 'face.jpg',
                'type'     => 'image/jpeg',
                'tmp_name' => '/tmp/a',
                'error'    => 0,
                'size'     => 100,
            ],
            'resume' => [
                'name'     => 'cv.pdf',
                'type'     => 'application/pdf',
                'tmp_name' => '/tmp/b',
                'error'    => 0,
                'size'     => 200,
            ],
        ];
        $result = Inspector::flattenFiles($files);
        $this->assertContains('face.jpg', $result);
        $this->assertContains('cv.pdf', $result);
        $this->assertCount(2, $result);
    }

    public function test_flatten_files_nested(): void
    {
        $files = [
            'uploads' => [
                'name'     => ['a' => 'one.jpg', 'b' => 'two.png'],
                'type'     => ['a' => 'image/jpeg', 'b' => 'image/png'],
                'tmp_name' => ['a' => '/tmp/a', 'b' => '/tmp/b'],
                'error'    => ['a' => 0, 'b' => 0],
                'size'     => ['a' => 100, 'b' => 200],
            ],
        ];
        $result = Inspector::flattenFiles($files);
        $this->assertContains('one.jpg', $result);
        $this->assertContains('two.png', $result);
        $this->assertCount(2, $result);
    }

    public function test_flatten_files_deeply_nested(): void
    {
        $files = [
            'uploads' => [
                'name'     => ['a' => ['b' => ['c' => 'deep.gif']]],
                'type'     => ['a' => ['b' => ['c' => 'image/gif']]],
                'tmp_name' => ['a' => ['b' => ['c' => '/tmp/c']]],
                'error'    => ['a' => ['b' => ['c' => 0]]],
                'size'     => ['a' => ['b' => ['c' => 300]]],
            ],
        ];
        $result = Inspector::flattenFiles($files);
        $this->assertEquals(['deep.gif'], $result);
    }

    public function test_flatten_files_empty(): void
    {
        $this->assertEquals([], Inspector::flattenFiles([]));
    }

}
