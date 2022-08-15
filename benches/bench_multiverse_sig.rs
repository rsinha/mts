use multiverse_signatures::{common::sig_utils, multiverse_sig::*, bls_sig::*};
use rand::{thread_rng};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn compute_crs(n: usize, k: usize) -> MultiverseParams {
    let mut rng = thread_rng();
    match k * n {
        x if x <= 10000 => sig_utils::test_setup::<10000>(&mut rng),
        x if x <= 20000 => sig_utils::test_setup::<20000>(&mut rng),
        x if x <= 30000 => sig_utils::test_setup::<30000>(&mut rng),
        x if x <= 40000 => sig_utils::test_setup::<40000>(&mut rng),
        x if x <= 50000 => sig_utils::test_setup::<50000>(&mut rng),
        x if x <= 60000 => sig_utils::test_setup::<60000>(&mut rng),
        x if x <= 70000 => sig_utils::test_setup::<70000>(&mut rng),
        x if x <= 80000 => sig_utils::test_setup::<80000>(&mut rng),
        x if x <= 90000 => sig_utils::test_setup::<90000>(&mut rng),
        x if x <= 100000 => sig_utils::test_setup::<100000>(&mut rng),
        x if x > 100000 => panic!("Can't handle CRS of this size"),
        _ => panic!("Unexpected!"),
    }
}

//N denotes number of parties, K denotes weight per party
fn bench_multiverse<const N: usize, const K: usize>(c: &mut Criterion) {

    let threshold : f64 = 0.5;
    let total_weight = K * N;
    let weight_threshold = ((total_weight as f64) * threshold) as usize;

    let crs = compute_crs(K,N);
    let addr_book = sig_utils::create_addr_book(N, K);

    let dealer = MultiverseParty::new(crs, weight_threshold, total_weight, &addr_book);

    let output = dealer.setup();

    let msg_to_sign = "Hello Multiverse";

    //let's collect signatures from 80 out of 100 parties
    let mut partial_sigs: Vec<MultiversePartialSig> = Vec::new();
    for id in 1..N {
        partial_sigs.push(dealer.sign(id, msg_to_sign.as_bytes(), &output));
    }

    c.bench_function(
        format!("multiverse_sign [N={}, K={}]", N, K).as_str(),
        |b| {
            b.iter(|| dealer.sign(
                black_box(1),
                black_box(msg_to_sign.as_bytes()),
                black_box(&output)));
        },
    );

    let aggregate_sig = dealer.aggregate(&output, &partial_sigs).unwrap();
    c.bench_function(
        format!("multiverse_aggregate [N={}, K={}]", N, K).as_str(),
        |b| {
            b.iter(|| dealer.aggregate(
                black_box(&output),
                black_box(&partial_sigs)));
        },
    );

    assert_eq!(dealer.verify(msg_to_sign.as_bytes(), &output, &aggregate_sig), true);
    c.bench_function(
        format!("multiverse_verify [N={}, K={}]", N, K).as_str(),
        |b| {
            b.iter(|| dealer.verify(
                black_box(msg_to_sign.as_bytes()),
                black_box(&output),
                black_box(&aggregate_sig)));
        },
    );
}

fn bench_bls<const N: usize, const K: usize>(c: &mut Criterion) {

    let threshold : f64 = 0.5;
    let total_weight = K * N;
    let weight_threshold = ((total_weight as f64) * threshold) as usize;

    let crs = compute_crs(K,N);
    let addr_book = sig_utils::create_addr_book(N, K);

    let dealer = BlsParty::new(crs, weight_threshold, total_weight, &addr_book);

    let output = dealer.setup();

    let msg_to_sign = "Hello Multiverse";

    //let's collect signatures from 80 out of 100 parties
    let mut partial_sigs: Vec<BlsPartialSig> = Vec::new();
    for id in 1..N {
        partial_sigs.push(dealer.sign(id, msg_to_sign.as_bytes(), &output));
    }

    /*
    c.bench_function(
        format!("bls_sign [N={}, K={}]", N, K).as_str(),
        |b| {
            b.iter(|| dealer.sign(
                black_box(1),
                black_box(msg_to_sign.as_bytes()),
                black_box(&output)));
        },
    );
    */

    let aggregate_sig = dealer.aggregate(&output, &partial_sigs).unwrap();
    c.bench_function(
        format!("bls_aggregate [N={}, K={}]", N, K).as_str(),
        |b| {
            b.iter(|| dealer.aggregate(
                black_box(&output),
                black_box(&partial_sigs)));
        },
    );

    /*
    assert_eq!(dealer.verify(msg_to_sign.as_bytes(), &output, &aggregate_sig), true);
    c.bench_function(
        format!("bls_verify [N={}, K={}]", N, K).as_str(),
        |b| {
            b.iter(|| dealer.verify(
                black_box(msg_to_sign.as_bytes()),
                black_box(&output),
                black_box(&aggregate_sig)));
        },
    );
    */
}

mod perf;

criterion_group!(
    name = multiverse_sig;
    config = Criterion::default().
        with_profiler(perf::FlamegraphProfiler::new(200)).
        sample_size(10);
    targets = bench_multiverse<100,1>,
        //bench_multiverse<100,10>,
        //bench_multiverse<100,50>,

        bench_multiverse<200,1>,
        //bench_multiverse<200,10>,
        //bench_multiverse<200,50>,

        bench_multiverse<500,1>,
        //bench_multiverse<500,10>,
        //bench_multiverse<500,50>,

        bench_multiverse<1000,1>,
        //bench_multiverse<1000,10>,
        //bench_multiverse<1000,50>,

        bench_multiverse<1500,1>,
        //bench_multiverse<1500,10>,
        //bench_multiverse<1500,50>,

        bench_multiverse<2000,1>,
        //bench_multiverse<2000,10>,
        //bench_multiverse<2000,50>,
);

criterion_group!(
    name = bls_sig;
    config = Criterion::default().
        with_profiler(perf::FlamegraphProfiler::new(200)).
        sample_size(10);
    targets = bench_bls<100,1>,
        bench_bls<100,10>,
        bench_bls<100,50>,

        bench_bls<200,1>,
        bench_bls<200,10>,
        bench_bls<200,50>,

        bench_bls<500,1>,
        bench_bls<500,10>,
        bench_bls<500,50>,

        bench_bls<1000,1>,
        bench_bls<1000,10>,
        bench_bls<1000,50>,

        bench_bls<1500,1>,
        bench_bls<1500,10>,
        bench_bls<1500,50>,

        bench_bls<2000,1>,
        bench_bls<2000,10>,
        bench_bls<2000,50>,
);

criterion_main!(multiverse_sig);
