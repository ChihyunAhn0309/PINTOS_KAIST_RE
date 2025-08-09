#define f (1<<14)

int int2fix(int n){
    return n * f;
}

int round2zero(int x){
    return x/f;
}

int round2near(int x){
    if(x >=0){
        return (x + (f/2))/f;
    }
    else{
        return (x - (f/2))/f;
    }
}

int faddf(int x, int y){
    return x + y;
}

int fsubf(int x, int y){
    return x - y;
}

int faddn(int x, int n){
    return x + n * f;
}

int fsubn(int x, int n){
    return x - n * f;
}

int nsubf(int n, int x){
    return n * f - x;
}

int fmulf(int x, int y){
    return ((int64_t) x) * y / f;
}

int fmuln(int x, int n){
    return x * n;
}

int fdivf(int x, int y){
    return ((int64_t) x) * f / y;
}

int fdivn(int x, int n){
    return ((int64_t) x) / n;
}
