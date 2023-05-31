# Models
 
Some checked-in models models, created with [zkp-gravity/BTHOWeN-0g](https://github.com/zkp-gravity/BTHOWeN-0g).

To update the models, follow the steps in the `BTHOWeN-0g` readme, then copy the models over:

```bash
cp ../BTHOWeN/software_model/models/MNIST/*.hdf5 models/
```

### "MNIST-Tiny": `model_28input_256entry_1hash_1bpi` (k = 12)

A very small toy model, used in the tests and the benchmark.
Accuracy on the MNIST test set is 83.06%.

### "MNIST-Small": `model_28input_1024entry_2hash_2bpi` (k = 15)

This model is comparable to the "MNIST-Small" model in the [BTHOWeN paper](https://arxiv.org/abs/2203.01479) (see Table III).
It has the same parameters, but uses the ["MishMash" hash function](https://hackmd.io/nCoxJCMlTqOr41_r1W4S9g?view#A-challenge-overcome-the-choice-of-hash-function) (`(x^3 % p) % 2^l`).

Accuracy on the MNIST test set is 92.81% (compares to 93.4% in the paper).

### "MNIST-Medium": `model_28input_2048entry_2hash_3bpi` (k = 15)

This model has the same parameters as the "MNIST-Medium" model in the BTHOWeN paper.

Accuracy on the MNIST test set is 93.95% (compares to 94.3% in the paper).

### "MNIST-Large": `model_49input_8192entry_4hash_6bpi` (k = 17)

This model has the same parameters as the "MNIST-Large" model in the BTHOWeN paper.

Accuracy on the MNIST test set is 95.10% (compares to 95.2% in the paper).