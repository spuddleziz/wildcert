export type DomainMap = {
    [domain: string]: string
}

export type OVHError = {
    message:string
    error: string
}

export type OVHZoneRecord = {
    fieldType:string;
    target:string;
    zone:string;
    subdomain: string;
    ttl:number;
    id:number; //OVH returns an ID with it's records
}
