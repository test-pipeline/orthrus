import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusSpectrum(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

    def compare_dice_json(self, file1, file2):

        expected_line_substring = 'src/main.cpp:main:37:5'

        with open(file1) as data_file1:
            data1 = json.load(data_file1)
        with open(file2) as data_file2:
            data2 = json.load(data_file2)

        self.assertEqual(data1["shrink-percent"], data2["shrink-percent"], 'Shrink percent did not match')
        self.assertEqual(data1["dice-linecount"], data2["dice-linecount"], 'Dice line count did not match')
        self.assertEqual(data1["slice-linecount"], data2["slice-linecount"], 'Slice line count did not match')
        self.assertEqual(data1["diff-node-spec"][0]["count"], data2["diff-node-spec"][0]["count"],
                         'Dice frequency did not match')
        self.assertTrue(expected_line_substring in data1["diff-node-spec"][0]["line"],
                        'Dice line did not match')
        self.assertEqual(data1["crashing-input"], data2["crashing-input"], 'Crashing input did not match')
        if 'parent-input' in data1 and 'parent-input' in data2:
            self.assertEqual(data1["parent-input"], data2["parent-input"], 'Parent input did not match')
        return True

    def compare_slice_json(self, file1, file2):
        with open(file1) as data_file1:
            data1 = json.load(data_file1)
        with open(file2) as data_file2:
            data2 = json.load(data_file2)
        self.assertEqual(data1["crashing-input"], data2["crashing-input"], 'Crashing input did not match')
        self.assertEqual(data1["slice-linecount"], data2["slice-linecount"], 'Slice line count did not match')
        return True

    def output_assert(self):
        # Output checks
        self.assertTrue(os.path.exists(self.dice_dir), "No dice dir generated")
        self.assertTrue(os.path.exists(self.slice_dir), "No slice dir generated")
        self.assertTrue(self.compare_slice_json(self.gen_slice, self.exp_slice))
        return True

    def output_assert_abtests(self):
        # Output checks
        for dir in self.abtest_dice_dirs:
            self.assertTrue(os.path.exists(dir), "No dice dir generated")
        for dir in self.abtest_slice_dirs:
            self.assertTrue(os.path.exists(dir), "No slice dir generated")

        for slice in self.abtest_gen_slices:
            self.assertTrue(self.compare_slice_json(slice, self.abtest_exp_slice))
        return True

    def test_spectrum(self):
        args = parse_cmdline(self.description, ['spectrum', '-j', self.add_cmd.job.id, '-q'])
        cmd = OrthrusSpectrum(args, self.config)
        self.assertTrue(cmd.run())

        # Output checks
        self.assertTrue(self.output_assert())
        self.assertTrue(self.compare_dice_json(self.gen_dice, self.exp_dice_single))

    def test_spectrum_sancovbug(self):
        args = parse_cmdline(self.description, ['spectrum', '-j', self.add_cmd.job.id, '-q', '--regenerate',
                                                '--sancov-bug'])
        cmd = OrthrusSpectrum(args, self.config)
        self.assertTrue(cmd.run())

        # Output checks
        self.assertTrue(self.output_assert())
        self.assertTrue(self.compare_dice_json(self.gen_dice, self.exp_dice_single))

    def test_version(self):
        args = parse_cmdline(self.description, ['spectrum', '-j', self.add_cmd.job.id, '--version'])
        cmd = OrthrusSpectrum(args, self.config)
        self.assertTrue(cmd.run())

    def tests_overwrite_dir(self):
        args = parse_cmdline(self.description, ['spectrum', '-j', self.add_cmd.job.id, '-q'])
        cmd = OrthrusSpectrum(args, self.config)
        self.assertFalse(cmd.run())

    def test_spectrum_abtest(self):
        args = parse_cmdline(self.description, ['spectrum', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusSpectrum(args, self.config)
        self.assertTrue(cmd.run())

        self.assertTrue(self.output_assert_abtests())
        for dice in self.abtest_gen_dices:
            self.assertTrue(self.compare_dice_json(dice, self.abtest_exp_dice))

    def test_spectrum_multiple(self):
        args = parse_cmdline(self.description, ['spectrum', '-j', self.add_cmd.job.id, '--dd-num=3', '--regenerate'])
        cmd = OrthrusSpectrum(args, self.config)
        self.assertTrue(cmd.run())

        # Output checks
        self.assertTrue(self.output_assert())
        self.assertTrue(self.compare_dice_json(self.gen_dice, self.exp_dice_multiple))

    def test_spectrum_multiple_sancovbug(self):
        args = parse_cmdline(self.description, ['spectrum', '-j', self.add_cmd.job.id, '--dd-num=3', '--regenerate',
                                                '--sancov-bug'])
        cmd = OrthrusSpectrum(args, self.config)
        self.assertTrue(cmd.run())

        # Output checks
        self.assertTrue(self.output_assert())
        self.assertTrue(self.compare_dice_json(self.gen_dice, self.exp_dice_multiple))

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-asan', '-fuzz', '-sancov'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        # Add routine job
        routineconf_dict = {'fuzzer': 'afl-fuzz', 'fuzzer_args': ''}
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)

        args = parse_cmdline(cls.description, ['add', '--job=main @@', '-i=./afl-crash-out.tar.gz', '--jobtype=routine',
                                               '--jobconf={}'.format(cls.routineconf_file)])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()
        # Start routine job fuzzing
        # args = parse_cmdline(cls.description, ['start', '-j', cls.add_cmd.job.id])
        # cmd = OrthrusStart(args, cls.config)
        # cmd.run()
        # time.sleep(2*TEST_SLEEP)
        # # Stop routine job fuzzing
        # args = parse_cmdline(cls.description, ['stop', '-j', cls.add_cmd.job.id])
        # cmd = OrthrusStop(args, cls.config)
        # cmd.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

        # Add a/b test job
        abconf_dict = {'num_jobs': 2, 'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast', 'fuzzerB_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '-i=./afl-crash-out.tar.gz', '--jobconf={}'.
                             format(cls.abconf_file), '--jobtype=abtests'])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtest.run()
        # Start a/b test job
        # args = parse_cmdline(cls.description, ['start', '-j', cls.add_cmd_abtest.job.id])
        # cmd = OrthrusStart(args, cls.config)
        # cmd.run()
        # time.sleep(2 * TEST_SLEEP)
        # # Stop a/b test job
        # args = parse_cmdline(cls.description, ['stop', '-j', cls.add_cmd_abtest.job.id])
        # cmd = OrthrusStop(args, cls.config)
        # cmd.run()
        # Simulate old triage
        sim_unique_dir = cls.orthrusdirname + '/jobs/abtests/{}/{}/unique'.format(cls.add_cmd_abtest.job.id,
                                                                         cls.add_cmd_abtest.job.jobids[0])
        if not os.path.isdir(sim_unique_dir):
            os.mkdir(sim_unique_dir)

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd_abtest.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

        ## Expected filenames
        cls.gen_dice = '{}/crash-analysis/spectrum/asan/dice/ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json' \
            .format(cls.add_cmd.job.rootdir)
        cls.exp_dice_single = './expects/asan/spectrum/dice/single/' \
                              'ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json'
        cls.exp_dice_multiple = './expects/asan/spectrum/dice/multiple/' \
                              'ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json'

        cls.gen_slice = '{}/crash-analysis/spectrum/asan/slice/ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json' \
            .format(cls.add_cmd.job.rootdir)
        cls.exp_slice = './expects/asan/spectrum/slice/ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json'

        cls.dice_dir = '{}/crash-analysis/spectrum/asan/dice'.format(cls.add_cmd.job.rootdir)
        cls.slice_dir = '{}/crash-analysis/spectrum/asan/slice'.format(cls.add_cmd.job.rootdir)

        ## Abtests
        cls.abtest_dice_dirs = ['{}/crash-analysis/spectrum/asan/dice'.format(rootdir) for rootdir in cls.add_cmd_abtest.rootdirs]
        cls.abtest_slice_dirs = ['{}/crash-analysis/spectrum/asan/slice'.format(rootdir) for rootdir in cls.add_cmd_abtest.rootdirs]

        cls.abtest_gen_slices = ['{}/crash-analysis/spectrum/asan/slice/' \
                                 'ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json'.format(rootdir) for rootdir in cls.add_cmd_abtest.rootdirs]
        cls.abtest_exp_slice = './expects/abtests/asan/spectrum/slice/ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json'

        cls.abtest_gen_dices = ['{}/crash-analysis/spectrum/asan/dice/' \
                                 'ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json'.format(rootdir) for rootdir in cls.add_cmd_abtest.rootdirs]
        cls.abtest_exp_dice = './expects/abtests/asan/spectrum/dice/ASAN:SESSION000:id:000000,sig:06,src:000000,op:havoc,rep:2.json'

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)