import http, { FractalResponseData, getPaginationSet, PaginatedResult } from '@/api/http';
import { createContext, useContext } from 'react';
import useSWR from 'swr';
import { Database, rawDataToDatabase } from '@/api/admin/databases/getDatabases';
import { Location, rawDataToLocation } from '@/api/admin/locations/getLocations';

export interface Node {
    id: number;
    uuid: string;
    public: boolean;
    name: string;
    description: string | null;
    locationId: number;
    databaseHostId: number | null;
    fqdn: string;
    listenPortHTTP: number;
    publicPortHTTP: number;
    listenPortSFTP: number;
    publicPortSFTP: number;
    scheme: string;
    behindProxy: boolean;
    maintenanceMode: boolean;
    memory: number;
    memoryOverallocate: number;
    disk: number;
    diskOverallocate: number;
    uploadSize: number;
    daemonBase: string;
    createdAt: Date;
    updatedAt: Date;

    relations: {
        databaseHost: Database | undefined;
        location: Location | undefined;
    };
}

export const rawDataToNode = ({ attributes }: FractalResponseData): Node => ({
    id: attributes.id,
    uuid: attributes.uuid,
    public: attributes.public,
    name: attributes.name,
    description: attributes.description,
    locationId: attributes.location_id,
    databaseHostId: attributes.database_host_id,
    fqdn: attributes.fqdn,
    listenPortHTTP: attributes.listen_port_http,
    publicPortHTTP: attributes.public_port_http,
    listenPortSFTP: attributes.listen_port_sftp,
    publicPortSFTP: attributes.public_port_sftp,
    scheme: attributes.scheme,
    behindProxy: attributes.behind_proxy,
    maintenanceMode: attributes.maintenance_mode,
    memory: attributes.memory,
    memoryOverallocate: attributes.memory_overallocate,
    disk: attributes.disk,
    diskOverallocate: attributes.disk_overallocate,
    uploadSize: attributes.upload_size,
    daemonBase: attributes.daemon_base,
    createdAt: new Date(attributes.created_at),
    updatedAt: new Date(attributes.updated_at),

    relations: {
        databaseHost: attributes.relationships?.database_host !== undefined ? rawDataToDatabase(attributes.relationships.database_host as FractalResponseData) : undefined,
        location: attributes.relationships?.location !== undefined ? rawDataToLocation(attributes.relationships.location as FractalResponseData) : undefined,
    },
});

interface ctx {
    page: number;
    setPage: (value: number | ((s: number) => number)) => void;
}

export const Context = createContext<ctx>({ page: 1, setPage: () => 1 });

export default (include: string[] = []) => {
    const { page } = useContext(Context);

    return useSWR<PaginatedResult<Node>>([ 'nodes', page ], async () => {
        const { data } = await http.get('/api/application/nodes', { params: { include: include.join(','), page } });

        return ({
            items: (data.data || []).map(rawDataToNode),
            pagination: getPaginationSet(data.meta.pagination),
        });
    });
};